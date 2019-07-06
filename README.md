# k8s-c7n-g3h
This is a basic kubernetes connection graph visualizer to evaluate the growth
and coupling of microsservice architecture built applications

## Requirements
Need to create link for libpcap.so.1 even if libpcap-dev is installed
libpcap.so.1

## Build

``` shell
export GO111MODULE=on
go build -o ./app -ldflags "-s -w" .
```

## Run in Dev Environment

### Teastore
To setup the Teastore microsservice architecture dev environment like Teastore,
you will need to use a orchestration environment like Kubernetes.

First, you need to turn on the Asynchronous Message System (RabbitMQ) for the Teastore:

``` shell
kubectl create -f https://raw.githubusercontent.com/DescartesResearch/TeaStore/master/examples/kubernetes/teastore-rabbitmq.yaml
```

This will be a central logging service that all services will comunicate with.

You need to wait 2 to 5 minutes for the service to become online and running.
Then start the instrumented version of the Teastore:

``` shell
kubectl create -f https://raw.githubusercontent.com/DescartesResearch/TeaStore/master/examples/kubernetes/teastore-ribbon-kieker.yaml
```

The main services will be available via localhost on ports 30080 (webui) and 30081(logs)

If you are done and want to remove everything, just do:

``` shell
kubectl delete pods,deployments,services -l app=teastore
```

### Running the Coupling Graph Creator Application:
With the compiled version of the app on the same machine as the cluster is running, do:

``` shell
./app
```

And follow the instructions. Basically you need to use the app and all it's functionalities for some time and then report back to the command line to get the output.
