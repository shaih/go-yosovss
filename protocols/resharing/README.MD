# YOSO proactive resharing protocol

## Indices

Indices:

* `i`: dealer in 0,...,n-1 contrary to paper!
* `l`: index of the first-level of sharing of the secret `s[i]` of the dealer `i`. Match next holding committee member `j`.
* `j`: verification committee member
* `k`: resolution committee member

Contrary to the paper, the indices of the committee members start at 0 and not at 1.

## Parameters

At the level of the protocol:
* `n`: number of parties per committee
* `t`: maximum number of malicious parties

`n = 2t+1`

However, for VSS / Secret Sharing, `t` usually represents the reconstruction threshold, which is degree `d` + 1.
And `d = t` from the protocol.

## Organization

Main files:
* `protocol.go`: the actual protocol
* `protocol_test.go`: test of the full protocol
* `protocol_bench_test.go`: test for benchmarking performances. See below.

* `step*.go`: for each round/step of the protocol. Step 4 is split in twoparts: resolution, then refreshing

Pieces of the protocol:
* `nizk_*.go`: for the internal NIZK
* `verifier_proof.go`: for the proof made by the verifier V_j
* `eps.go`: for things related to the future broadcast/resolution encryption

Other tools:
* `codecgen.go`: used to have faster encoding/decoding. Generate `gen-codecgen.go`
* `inputs.go`: structure of the public and private inputs
* `receive.go`: generate `gen-receive.go`
* `test_tools*.go`: tools for testing

## Benchmark

For large values n/t, simulating the whole protocol is too slow, so we use `TestResharingProtocolBenchmarkManualParty0`:

```bash
YOSO_BENCH_TEST_T=32 go test -timeout=2h -bench -v -run TestResharingProtocolBenchmarkManualParty0
```