package hdwallet

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const addressChecksumLen = 4

//CheckSum get checksum
func CheckSum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:addressChecksumLen]
}

//ToBTC convert public key to BTC address of P2PKH
func ToBTC(pubkey []byte, isSegwit bool) string {
	if !isSegwit {
		//new method
		P2PKHAddr, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pubkey), &chaincfg.MainNetParams)
		if err != nil {
			return ""
		}

		address := P2PKHAddr.EncodeAddress()

		return address
	}

	//P2Sh with P2WPKH
	address, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubkey), &chaincfg.MainNetParams)
	if err != nil {
		return ""
	}

	pkScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		return ""
	}

	scriptAddr, err := btcutil.NewAddressScriptHash(
		pkScript, &chaincfg.MainNetParams)
	if err != nil {
		return ""
	}

	segwitAddress := scriptAddr.EncodeAddress()

	return segwitAddress
}

//ToETH convert public key to ETH address
func ToETH(pubkey []byte) string {
	common := common.BytesToAddress(crypto.Keccak256(pubkey[1:])[12:])
	return common.String()
}

//ToEOS convert public key to EOS address
func ToEOS(pubkey []byte) string {
	//1.ripemd160
	ripemder := ripemd160.New()
	ripemder.Write(pubkey)
	pubKeyHash := ripemder.Sum(nil)

	//2. checksum
	checksum := pubKeyHash[:4]

	//3. add version
	payload := append(pubkey, checksum...)

	address := "EOS" + base58.Encode(payload)
	return address
}

//ToVEX convert public key to VEX address
func ToVEX(pubkey []byte) string {
	//1.ripemd160
	ripemder := ripemd160.New()
	ripemder.Write(pubkey)
	pubKeyHash := ripemder.Sum(nil)

	//2. checksum
	checksum := pubKeyHash[:4]

	//3. add version
	payload := append(pubkey, checksum...)

	address := "VEX" + base58.Encode(payload)
	return address
}

//ToIOST convert public key to IOST address
func ToIOST(pubkey []byte) string {
	//1.ripemd160
	ripemder := ripemd160.New()
	ripemder.Write(pubkey)
	pubKeyHash := ripemder.Sum(nil)

	//2. checksum
	checksum := pubKeyHash[:4]

	//3. add version
	payload := append(pubkey, checksum...)

	address := "EOS" + base58.Encode(payload)
	return address
}
