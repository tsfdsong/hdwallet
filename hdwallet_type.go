package hdwallet

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
)

//GetCoinIndex return bip44 coin index from coin type.  DOC: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
func GetCoinIndex(coinType string) (index int, err error) {
	switch coinType {
	case "BTC":
		index = 0
	case "LTC":
		index = 2
	case "ETH":
		index = 60
	case "ETC":
		index = 61
	case "FCT":
		index = 131
	case "EOS":
		index = 194
	case "VEX":
		index = 194
	case "IOST":
		index = 291
	default:
		err = fmt.Errorf("coin type %s is not support", coinType)
	}

	return index, err
}

//PublicKeyToAddress convert public key to address
func PublicKeyToAddress(coinType string, pubkey *btcec.PublicKey, isSegwit bool) (key string, addr string, err error) {
	pubkeyBytes := pubkey.SerializeCompressed()

	switch coinType {
	case "BTC":
		{
			if isSegwit {
				//segwit publickey
				secH160bytes := btcutil.Hash160(pubkeyBytes)

				key = hex.EncodeToString(secH160bytes)

				//segwit address
				addr = ToBTC(pubkeyBytes, true)

			} else {
				key = hex.EncodeToString(pubkeyBytes)
				addr = ToBTC(pubkeyBytes, false)
			}
		}
	case "LTC":
	case "ETH":
		key = hex.EncodeToString(pubkeyBytes)
		addr = ToETH(pubkeyBytes)
	case "ETC":
	case "EOS":
		key = hex.EncodeToString(pubkey.SerializeUncompressed())

		addr = ToEOS(pubkeyBytes)
	case "VEX":
		key = hex.EncodeToString(pubkey.SerializeUncompressed())

		addr = ToVEX(pubkeyBytes)
	default:
		err = fmt.Errorf("coin type %s is not support when converting to address", coinType)
	}

	return key, addr, err
}
