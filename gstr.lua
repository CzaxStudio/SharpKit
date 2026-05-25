
local Vector2D = {}
Vector2D.__index = Vector2D


function Vector2D.new(x, y)
    local self = setmetatable({}, Vector2D)
    self.x = x or 0
    self.y = y or 0
    return self
end

function Vector2D:add(other)
    self.x = self.x + other.x
    self.y = self.y + other.y
end


function Vector2D:toString()
    return string.format("Vector2D(X: %.1f, Y: %.1f)", self.x, self.y)
end
