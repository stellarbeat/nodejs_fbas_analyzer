# fbas_analyzer_nodejs

Uses https://neon-bindings.com/ to create a nodejs module around the awesome https://github.com/wiberlin/fbas_analyzer tool.

Uses https://travis-ci.org/ to build binaries for linux & mac os (https://neon-bindings.com/docs/publishing)

## build release
`yarn install`

## build dev
`neon build`

## cleanup
`neon clean`

Cleans up native folder. 

## upgrade fbas_analyzer rust package

Update the version in Cargo.toml
```
cd native
cargo build
```
