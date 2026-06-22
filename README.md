# compile
```bash
make clean
make
```

# run
```bash
mosquitto -c mosquitto.conf
```

# test
```bash
mosquitto_pub -h localhost -p 1884 -t "test/edge/waf" -m "Hello from the local edge device"
```
