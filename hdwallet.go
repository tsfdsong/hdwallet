package hdwallet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/tyler-smith/go-bip39"
)

//Wallet manage the object of wallet
type Wallet struct {
	Mnemonic  string
	MasterKey *hdkeychain.ExtendedKey
	CoinType  string

	Entropy string
	Seed    string
}

//CreateMnemonic create mnemonic if the input mnemonic is empty
func CreateMnemonic(mnemonic string) (string, error) {
	if mnemonic == "" {
		//check mnemonic is empty
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return "", err
		}

		tmp, err := bip39.NewMnemonic(entropy)
		if err != nil {
			return "", err
		}

		fmt.Printf("Create mnemonic: %v    %v\n", string(entropy), tmp)

		mnemonic = tmp
	}

	return mnemonic, nil
}

//NewWallet return a new wallet from a BIP-39 mnemonic
func NewWallet(mnemonic, coinType string) (*Wallet, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invaild")
	}

	enbyte, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	hexEntropy := hex.EncodeToString(enbyte)

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		return nil, err
	}
	hexSeed := hex.EncodeToString(seed)

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		Mnemonic:  mnemonic,
		MasterKey: masterKey,
		CoinType:  coinType,
		Entropy:   hexEntropy,
		Seed:      hexSeed,
	}, nil
}

// DerivePrivateKey derives the private key of the derivation path.
func (w *Wallet) DerivePrivateKey(path string) (*btcec.PrivateKey, error) {
	key := w.MasterKey

	dpath, err := ParseDerivationPath(path)
	if err != nil {
		return nil, err
	}

	for _, n := range dpath {
		key, err = key.Child(n)
		if err != nil {
			return nil, err
		}
	}

	privateKeyECDSA, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}

	return privateKeyECDSA, nil
}

// DerivePublicKey derives the public key of the derivation path.
func (w *Wallet) DerivePublicKey(path string) (*btcec.PublicKey, error) {
	privateKeyECDSA, err := w.DerivePrivateKey(path)
	if err != nil {
		return nil, err
	}

	publicKeyECDSA := privateKeyECDSA.PubKey()

	return publicKeyECDSA, nil
}

//GetWalletID get wallet id
func (w *Wallet) GetWalletID() (string, error) {
	masterKey := w.MasterKey

	pubKey, err := masterKey.ECPubKey()
	if err != nil {
		return "", err
	}

	pub := btcec.PublicKey(*pubKey)
	pubkeyBytes := pub.SerializeCompressed()

	hasher1 := sha256.New()
	hasher1.Write(pubkeyBytes)
	res1 := hasher1.Sum(nil)

	hasher2 := sha256.New()
	hasher2.Write(res1)
	res2 := hasher2.Sum(nil)

	walleID := hex.EncodeToString(res2)

	return walleID, nil
}

//GetPrivateKey get hex private
func (w *Wallet) GetPrivateKey(coinType string, index int, isSegwit bool) (string, error) {
	coinIndex, err := GetCoinIndex(coinType)
	if err != nil {
		return "", err
	}

	var bipPath string
	if isSegwit {
		bipPath = fmt.Sprintf("m/49'/%d'/0'/0/%d", coinIndex, index)
	} else {
		bipPath = fmt.Sprintf("m/44'/%d'/0'/0/%d", coinIndex, index)
	}

	esdsaPrivateKey, err := w.DerivePrivateKey(bipPath)
	if err != nil {
		return "", err
	}

	priKey := btcec.PrivateKey(*esdsaPrivateKey)
	priBytes := priKey.Serialize()
	priKeyHex := hex.EncodeToString(priBytes)

	return priKeyHex, nil
}

//GetKeyAndAddress get hex publickey and address
func (w *Wallet) GetKeyAndAddress(coinType string, index int, isSegwit bool) (string, string, error) {
	ecdsaPriKeyHex, err := w.GetPrivateKey(coinType, index, isSegwit)
	if err != nil {
		return "", "", err
	}

	priBytes, err := hex.DecodeString(ecdsaPriKeyHex)
	if err != nil {
		return "", "", err
	}

	_, ecdsaPubKey := btcec.PrivKeyFromBytes(btcec.S256(), priBytes)

	return PublicKeyToAddress(coinType, ecdsaPubKey, isSegwit)
}

//GetKeyAndAddressSegwit get hex publickey and segwit address
func (w *Wallet) GetKeyAndAddressSegwit(coinType string, index int) (string, string, error) {
	ecdsaPriKeyHex, err := w.GetPrivateKey(coinType, index, true)
	if err != nil {
		return "", "", err
	}

	priBytes, err := hex.DecodeString(ecdsaPriKeyHex)
	if err != nil {
		return "", "", err
	}

	_, ecdsaPubKey := btcec.PrivKeyFromBytes(btcec.S256(), priBytes)
	pubkeyBytes := ecdsaPubKey.SerializeCompressed()

	//segwit publickey
	secH160bytes := btcutil.Hash160(pubkeyBytes)

	segwitPublicKey := hex.EncodeToString(secH160bytes)

	//segwit address
	segwitAddress := ToBTC(pubkeyBytes, true)

	return segwitPublicKey, segwitAddress, nil
}
