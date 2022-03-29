init_data:export EGO_DEBUG=true
init_data:
	go run server/main.go --config=server/config/local.toml --job=init_data

run_client:export EGO_DEBUG=true
run_client:
	go run client/main.go --config=client/config/local.toml

run_server:export EGO_DEBUG=true
run_server:
	go run server/main.go --config=server/config/local.toml

build_proto:
	protoc -I ./proto --go_out=paths=source_relative:./proto ./proto/*.proto
	protoc -I ./proto --go-grpc_out=paths=source_relative:./proto ./proto/*.proto