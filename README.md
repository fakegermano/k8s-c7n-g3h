# k8s-c7n-g3h
This is a basic kubernetes connection graph visualizer to evaluate the growth
and coupling of microsservice architecture built applications

## Requirements
Need to create link for libpcap.so.1 even if libpcap-dev is installed
libpcap.so.1

## Build

``` shell
export GO111MODULE=on
go build -o ./app .
```

## Run

``` shell
./app
```
