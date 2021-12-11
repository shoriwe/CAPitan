# Sniffer scripting

The sniffer module provides a scripting functionality to properly filter TCP streams and network packets.

You can expect this modules to be loaded in the plasma runtime:

- json
- regex
- base64

## Filtering TCP streams

To filter TCP streams you will implement callback function in the plasma programming language.

The implemented function will receive two arguments and the application is specked to receive a Boolean value from your function.

The Skeleton of the scripting function is:

```ruby
def YourTCPStreamFilter(contentType, data)
    
    # Your code here
    
    return result # result is a boolean value
end
```

The `contentType` variable have the mime type detected by the engine so it could be for example:

- text/plain
- application/javascript
- text/html
- image/gif
- unknown

For HTTP requests and responses, the value of `contentType` will be:

- text/http-request
- text/http-response

The `data` variable have the raw bytes of the TCP stream in case you want to processed them.

### Example functions

- Do not capture TCP streams of unknown Type

```ruby
def ignoreUnknowns(contentType, _) # Notice that we don't care about the second argument in this example
    return contentType != "unknown"
end
```

- Capture any of wanted ones

```ruby
targets = ("text/plain", "image/gif", "application/json")

def captureTargets(contentType, _)
    return contentType in targets
end
```

## Filtering Packets

To filter individual packets you will implement a callback function in the plasma programming language.

The implemented function will receive one argument and the application is specked to receive a Boolean value from your function.

The Skeleton of the scripting function is:

```ruby
def YourPacketFilter(packet)
    
    # Your code here
    
    return result # result is a boolean value
end
```

The `packet` variable receives a plasma HashMap with this structure

```json
{
    "Metadata": {
        "Length": 0,
        "CaptureLength": 0,
        "Truncated": false,
        "InterfaceIndex": 0.
    },
    "TransportLayer": {
        "LayerType": "",
        "LayerPayload": "",
        "LayerContents": "",
        "TransportFlow": {
            "String": "",
            "Src": "",
            "Dst": "",
            "EndpointType": ""
        }
    },
    "ApplicationLayer": {
        "LayerType": "",
        "LayerPayload": "",
        "LayerContents", "",
        "Payload": ""
    },
    "NetworkLayer": {
        "LayerType": "",
        "LayerPayload": "",
        "LayerContents": "",
        "NetworkFlow": {
            "Src": "",
            "Dst": "",
            "String": "",
            "EndpointType": ""
        }
    },
    "LinkLayer": {
        "LayerType": "",
        "LayerPayload": "",
        "LayerContents": "",
        "LinkFlow": {
            "Src": "",
            "Dst": "",
            "String": "",
            "EndpointType": ""
        }
    },
    "ErrorLayer": {
        "LayerType": "",
        "LayerPayload": "",
        "LayerContents": "",
        "ErrorFlow": ""
    }
}
```

### Example functions

- Ignore any packet with target IP as Src or Dst

```ruby
target = "192.168.1.33"

def filterAnyNotTarget(packet)
    src = packet["NetworkLayer"]["NetworkFlow"]["Src"]
    dst = packet["NetworkLayer"]["NetworkFlow"]["Dst"]
    return src != target and dst != target
end
```



## Loading your filters

Once you have prepared your filter functions, you can load them inside the engine with `LoadTCPStreamFilter` for your TCP stream filter function and `LoadPacketFilter` for your packet filter function.

### Example

#### Loading TCP Stream filter

```ruby
targets = ("text/plain", "image/gif", "application/json")

def captureTargets(contentType, _)
    return contentType in targets
end

LoadTCPStreamFilter(captureTargets)
```

#### Loading Packets filter

```ruby
target = "192.168.1.33"

def filterAnyNotTarget(packet)
    src = packet["NetworkLayer"]["NetworkFlow"]["Src"]
    dst = packet["NetworkLayer"]["NetworkFlow"]["Dst"]
    return src != target and dst != target
end

LoadPacketFilter(filterAnyNotTarget)
```

