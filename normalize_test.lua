local dec = require("chuye_dec")
local f = io.open("test.luac", "rb")
local content = f:read("*a")
f:close()
local wrapped = content:match('"(.-)"') or content:match("'(.-)'") or content
local ok, err = pcall(dec.normalize, wrapped, "test_normalized.luac")
if not ok then print("Error: " .. err) end
