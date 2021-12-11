# ARP scanner scripting

The ARP scanner functionality permits the user to specify programmatically which targets it will try to scan.

This is done by loading a Generator like object in the the engine using the function `LoadHostGenerator`

A Generator like object is any object that implements `HasNext(): Boolean` and `Next(): Value`

## Example scripts

- Using built-in generator expression

```ruby
hosts = ("192.168.1." + number.ToString() for number in range(1, 256, 1))

LoadHostGenerator(hosts)
```

- Creating a custom generator

```ruby
class Hosts
    def Initialize()
        self.a = 0
        self.b = 0
    end
    
    def HasNext()
        return self.a != 255 and self.b != 255
    end
    
    def Next()
        host = "192.168." + self.a.ToString() + "." + self.b.ToString()
        if self.b == 255
            self.a += 1
            self.b = 0
        else
            self.b += 1
        end
        return host
    end
end

LoadHostGenerator(Hosts())
```

