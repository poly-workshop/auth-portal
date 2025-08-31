# Contributing to Auth Portal

欢迎任何形式的贡献！无论是修复 bug、添加新功能，还是改进文档，我们都非常感谢您的参与。以下是一些指导方针，帮助您更好地贡献代码。

## 选型

- 使用 gRPC 作为主要的通信协议，提供高效且类型安全的接口。
  - 使用 Buf 进行 Protobuf 的管理和代码生成，简化开发流程。
  - 使用 github.com/grpc-ecosystem/grpc-gateway/v2 提供 RESTful API 支持，方便与前端和其他服务集成。

## 开发指引

### 安装

无论什么系统都建议使用 brew 来管理安装 go 和 protoc 相关的工具。

```sh
go install \
    github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway \
    github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
    google.golang.org/protobuf/cmd/protoc-gen-go \
    google.golang.org/grpc/cmd/protoc-gen-go-grpc

brew install bufbuild/buf/buf
```

### 生成代码

```sh
buf dep update
buf generate
```
