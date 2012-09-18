import sys
import StringIO

import btcaddress
from bitcoin import core, script
import bitcoinrpc

TESTNET = True
RPCUSER = "test"
RPCPASS = "123"
RPCHOST = "localhost"
RPCPORT = 19001

btcconn = bitcoinrpc.connect_to_remote(RPCUSER, RPCPASS, RPCHOST, RPCPORT)

def decodetx(tx):
    rawtx = StringIO.StringIO(tx.decode("hex"))
    tx = core.CTransaction()
    tx.deserialize(rawtx)
    return tx

def create_new_contract(btcamount, address):
    """Creates a new bitcoin transaction contract for btcamount of satoshis,
    sending them to address.
    This transaction will have zero inputs and a single output and is thus
    invalid: people that want to pledge bitcoins to this contract will make
    inputs. Once we get enough inputs then the transaction can be sent to the
    bitcoin network, sending the bitcoins to the specified address."""

    txout = core.CTxOut()
    txout.nValue = btcamount

    #This creats a standard send-to-address transaction

    #We need to remove the first byte, which is the version
    keyhash = btcaddress.base58checksum_decode(address)[1:]
    txout.scriptPubKey = chr(script.OP_DUP) + \
        chr(script.OP_HASH160) + \
        chr(len(keyhash)) + \
        keyhash + \
        chr(script.OP_EQUALVERIFY) + \
        chr(script.OP_CHECKSIG)

    tx = core.CTransaction()
    tx.vout = [txout]
    print "Contract tx:"
    print "Amount: ", btcamount / 100000000
    print "To: " , address
    print tx.serialize().encode("hex")

def pledge_bitcoins(contracttx, btcamount):
    """Pledges btcamount of satoshis for assurance contract contracttx. This
    will do the following:
    1) Send btcamount to a newly created bitcoin address
    2) Make a new transaction, adding those bitcoins as only input and signs
       that transaction
    3) Returns the signed input"""

    #Create a new bitcoin address to send the pledge to
    privkey, address = btcaddress.create_new_address(TESTNET)

    #Sends btcamount of bitcoins to this new address
    txid = btcconn.sendtoaddress(address, btcamount / 100000000)

    print "Sent " + str(btcamount / 100000000) + "BTC to address " + address
    print "(private key: " + privkey+ ")"
    print "TXId: " + txid
    print

    #Retrieve the full transaction
    txhex = btcconn.getrawtransaction(txid)
    tx = decodetx(txhex)
    #And try to find the output we need
    for n, txout in enumerate(tx.vout):
        if txout.nValue == btcamount:
            print "TXOut: " + txid + ":" + str(n)
            break

    #Create the input to sign
    txintosign = core.CTxIn()
    txintosign.prevout.hash = long(txid, 16)
    txintosign.prevout.n = n
    #And add it to the contract transaction
    contracttx = decodetx(contracttx)
    contracttx.vin = [txintosign]
    contracttxser = contracttx.serialize().encode("hex")

    #Now finally sign it, using the signrawtransaction rpc command. Since this
    #is a new transaction that is not in the bitcoin wallet, we need to provide
    #it's private key.
    print "Signing transaction..."
    result = btcconn.signrawtransaction(contracttxser, None, [privkey], \
            "ALL|ANYONECANPAY")

    #We'll deserialize the resulting transaction and print the signed input
    tx = decodetx(result["hex"])
    txinsigned = tx.vin[0]
    print
    print "Signed input:"
    print txinsigned.serialize().encode("hex")


def finalize_contract(contracttx, inputfiles):
    """Adds every input written in inputfiles to the contract transaction and
    broadcasts it to the network."""
    contracttx = decodetx(contracttx)
    contracttxser = contracttx.serialize().encode("hex")

    for inp in open(inputfiles, "r").readlines():
        rawinp = StringIO.StringIO(inp.strip().decode("hex"))
        ctxin = core.CTxIn()
        ctxin.deserialize(rawinp)
        contracttx.vin.append(ctxin)

    fulltx = contracttx.serialize().encode("hex")
    print "Sending raw tx..."
    print fulltx
    print btcconn.sendrawtransaction(fulltx)



if __name__ == "__main__":
    if sys.argv[1] == "createcontract":
        address = sys.argv[2]
        amount = int(sys.argv[3])
        create_new_contract(amount, address)
    elif sys.argv[1] == "pledge":
        tx = sys.argv[2]
        amount = int(sys.argv[3])
        pledge_bitcoins(tx, amount)
    elif sys.argv[1] == "finalize":
        tx = sys.argv[2]
        inpf = sys.argv[3]
        finalize_contract(tx, inpf)

