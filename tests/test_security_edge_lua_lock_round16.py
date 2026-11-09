"""The generated Lua edge must recover a dead updater without losing denies."""
from __future__ import annotations

import shutil
import subprocess
from unittest import SkipTest

from dataplane.engine.services import edge_config


def _run_lua(steps: str) -> None:
    lua = shutil.which("lua") or shutil.which("luajit")
    if not lua:
        raise SkipTest("Lua runtime unavailable for generated edge verification")
    conf = edge_config.edge_proxy_config()
    loader = conf.split("init_worker_by_lua_block {", 1)[1].split("\n}\n\nserver", 1)[0]
    access = conf.split("access_by_lua_block {", 1)[1].split("\n        }", 1)[0]
    script = r'''
local data, now, file, pause_read, callback = {}, 0, "192.0.2.9\n", false, nil
local peer = "203.0.113.88"
local dict = {}
local function record(k)
    local r = data[k]
    if r and r.exp and r.exp <= now then data[k] = nil; return nil end
    return r
end
function dict:get(k) local r = record(k); return r and r.value end
function dict:safe_add(k,v,ttl)
    if record(k) then return nil, "exists" end
    data[k] = {value=v, exp=ttl and ttl > 0 and now + ttl or nil}
    return true
end
function dict:safe_set(k,v,ttl)
    if _G.reject_ban and k:find(_G.reject_ban, 1, true) then return nil, "no memory" end
        if _G.ban_key_capacity and k:match("^__ducknet_ban_") and not record(k) then
            local count = 0
            for key in pairs(data) do
                if key:match("^__ducknet_ban_") and record(key) then count = count + 1 end
            end
            if count >= _G.ban_key_capacity then return nil, "no memory" end
        end
    data[k] = {value=v, exp=ttl and ttl > 0 and now + ttl or nil}
    return true
end
function dict:set(k,v,ttl) return self:safe_set(k,v,ttl) end
function dict:incr(k,delta,initial)
    if _G.reject_epoch then return nil, "no memory" end
    local r = record(k)
    if not r and initial == nil then return nil, "not found" end
    local value = (r and r.value or initial) + delta
    data[k] = {value=value}
    return value
end
function dict:delete(k) data[k] = nil end
function dict:get_keys()
    local out = {}
    for k in pairs(data) do if record(k) then out[#out+1] = k end end
    return out
end
ngx = { shared={ducknet_ban=dict}, worker={id=function() return 0 end,
        pid=function() return 9123 end}, now=function() return now end,
        var=setmetatable({}, {__index=function(_,k) if k=="remote_addr" then return peer end end}),
        exit=function(code) return code end,
        timer={every=function(_,fn) callback=fn; return true end}, log=function() end }
io.open = function()
    local snapshot = file
    return {close=function() end, read=function(_,n)
        assert(n <= 8*1024*1024+1, "unbounded banlist read")
        if pause_read then pause_read=false; coroutine.yield("stalled loader") end
        return snapshot
    end}
end
local function bootstrap()
''' + loader + r'''
end
local function access_request(ip)
    peer = ip
''' + access + r'''
end
local function allowed(ip) return access_request(ip) == nil end
bootstrap()
assert(callback, "reload timer missing")
assert(not allowed("192.0.2.9"), "initial BAN bypassed")
assert(allowed("203.0.113.88"), "initial benign peer denied")
''' + steps
    result = subprocess.run([lua, "-"], input=script, text=True,
                            capture_output=True, timeout=8)
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_dead_worker_lock_recovers_and_late_writer_cannot_erase_new_ban():
    _run_lua(r'''
file = "192.0.2.9\n"
pause_read = true
local old = coroutine.create(callback)
local ok, why = coroutine.resume(old)
assert(ok and why == "stalled loader", "updater did not suspend while owning lock")
assert(not allowed("203.0.113.88"), "active updater released benign traffic")
file = "198.51.100.7\n"
now = now + 31
assert(not allowed("203.0.113.88"), "expired updater released unchecked traffic")
callback() -- replacement worker after the old owner's lease expired
assert(not allowed("198.51.100.7"), "replacement failed to install new BAN")
assert(allowed("203.0.113.88"), "dead updater permanently denied benign traffic")
assert(coroutine.resume(old), "old worker could not finish late")
assert(not allowed("198.51.100.7"), "late old writer erased replacement BAN")
assert(allowed("203.0.113.88"), "late old writer cleared newer readiness")
callback()
assert(not allowed("198.51.100.7"), "later refresh lost current BAN")
assert(allowed("203.0.113.88"), "late writer caused permanent outage")
''')


def test_generation_swap_unbans_and_capacity_failure_recovers():
    _run_lua(r'''
file = "198.51.100.7\n"
callback()
assert(allowed("192.0.2.9"), "old BAN survived successful generation swap")
assert(not allowed("198.51.100.7"), "new BAN missing after generation swap")
file = "198.51.100.8\n"
_G.reject_ban = "198.51.100.8"
callback()
assert(not allowed("203.0.113.88"), "capacity failure reopened backend")
_G.reject_ban = nil
callback()
assert(allowed("203.0.113.88"), "capacity recovery kept all clients denied")
assert(not allowed("198.51.100.8"), "capacity recovery lost BAN")
assert(allowed("198.51.100.7"), "old generation remained active after unban")
''')


def test_unchanged_file_renews_readiness_without_rebuilding_keys():
    _run_lua(r'''
local first_attempt = dict:get("__ducknet_epoch")
local first_generation = tonumber(dict:get("__ducknet_ready"):match("^%d+:(%d+)$"))
now = now + 11
callback()
assert(dict:get("__ducknet_epoch") == first_attempt + 1, "refresh lacked an atomic admission fence")
assert(dict:get("__ducknet_ready") == (first_attempt + 1) .. ":" .. first_generation,
       "unchanged file rebuilt all BAN keys")
assert(not dict:get("__ducknet_ban_" .. (first_attempt + 1) .. ":192.0.2.9"),
       "unchanged file staged redundant BAN keys")
now = now + 15
assert(allowed("203.0.113.88"), "renewed readiness expired prematurely")
now = now + 6
assert(not allowed("203.0.113.88"), "dead reload timer left stale snapshot green")
callback()
assert(dict:get("__ducknet_ready") == dict:get("__ducknet_epoch") .. ":" .. dict:get("__ducknet_epoch"),
       "expired readiness reused unverified keys")
assert(not allowed("192.0.2.9"), "recovery lost the listed BAN")
assert(allowed("203.0.113.88"), "recovery did not restore benign traffic")
''')


def test_replacement_worker_rebuilds_its_own_cache_from_file():
    _run_lua(r'''
local generation = dict:get("__ducknet_epoch")
bootstrap() -- a new worker0 has no process-local verified raw snapshot
assert(dict:get("__ducknet_epoch") > generation, "replacement reused old process cache")
assert(not allowed("192.0.2.9"), "replacement lost the listed BAN")
assert(allowed("203.0.113.88"), "replacement denied benign traffic")
''')


def test_epoch_allocation_failure_denies_until_retry():
    _run_lua(r'''
_G.reject_epoch = true
callback()
assert(not allowed("203.0.113.88"), "epoch allocation failure reused stale readiness")
_G.reject_epoch = nil
callback()
assert(not allowed("192.0.2.9"), "retry lost the old BAN")
assert(allowed("203.0.113.88"), "retry did not restore benign service")
''')


def test_partial_capacity_failure_is_reclaimed_before_smaller_retry():
    _run_lua(r'''
local many = {}
for i=1,9 do many[#many+1] = "198.51.100." .. i end
file = table.concat(many, "\n") .. "\n"
_G.ban_key_capacity = 5
callback()
assert(not allowed("203.0.113.88"), "partial capacity failure opened backend")
local failed_attempt = dict:get("__ducknet_epoch")
local partial = 0
for _, key in ipairs(dict:get_keys()) do
    if key:match("^__ducknet_ban_" .. failed_attempt .. ":") then partial = partial + 1 end
end
assert(partial > 0, "capacity failure did not stage partial state")
file = "203.0.113.9\n"
callback()
assert(allowed("203.0.113.88"), "partial old generation prevented valid retry")
assert(not allowed("203.0.113.9"), "smaller retry lost its BAN")
assert(allowed("192.0.2.9"), "smaller retry did not release old BAN")
''')
