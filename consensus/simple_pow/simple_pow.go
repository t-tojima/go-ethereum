package simple_pow

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"math/big"
)

type SimplePow struct {
}

func New() *SimplePow {
	return &SimplePow{}
}

func hashBlockWithNonce(number *big.Int, nonce uint64) (string, error) {
	blockNonce := types.EncodeNonce(nonce)

	buf := bytes.NewBuffer(number.Bytes())
	buf.Write(blockNonce[:])

	hashed := fmt.Sprintf("%x", sha256.Sum256(buf.Bytes()))
	return hashed, nil
}

func checkNonce(hash string) {
	for _, b := range hash[len(hash)-12:] {
		if b != '0' {
			return
		}
	}
	log.Info(fmt.Sprintf("checkNonce=%s", hash))
}

func isValidNonce(number *big.Int, nonce uint64) (bool, error) {
	hash, err := hashBlockWithNonce(number, nonce)
	if err != nil {
		return false, err
	}

	for _, b := range hash[len(hash)-6:] {
		if b != '0' {
			return false, nil
		}
	}

	return true, nil
}

func (s *SimplePow) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	log.Info(fmt.Sprintf("currentHeaderNumber: %d", chain.CurrentHeader().Number.Uint64()))
	log.Info(fmt.Sprintf("sealing block: number=%d", block.Number().Uint64()))
	header := types.CopyHeader(block.Header())

	nonce := uint64(0)
	for {
		select {
		case <-stop:
			log.Info("seal discarded")
			return nil, nil
		default:
			for i := 0; i < 1000000; i++ {
				isValid, err := isValidNonce(block.Header().Number, nonce)
				if err != nil {
					return nil, err
				}
				if isValid {
					log.Info(fmt.Sprintf("nonce found!=%d", nonce))
					header.Nonce = types.EncodeNonce(nonce)
					header.MixDigest = common.Hash{}
					return block.WithSeal(header), nil
				}
				nonce++
			}
			log.Info(fmt.Sprintf("calculating nonce=%d", nonce))
		}
	}
}

func (s *SimplePow) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (s *SimplePow) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	// no check
	return nil
}

func (s *SimplePow) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// no check
	abort := make(chan struct{})
	errorsOut := make(chan error, len(headers))
	for i := 0; i < len(headers); i++ {
		errorsOut <- nil
	}
	return abort, errorsOut
}

func (s *SimplePow) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	return nil
}

func (s *SimplePow) Prepare(chain consensus.ChainReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = ethash.CalcDifficulty(chain.Config(), header.Time.Uint64(), parent)
	return nil
}

func (s *SimplePow) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	ok, err := isValidNonce(header.Number, header.Nonce.Uint64())
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid pow")
	}
	return nil
}

func (s *SimplePow) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB,
	txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	log.Trace("SimplePow.finalize")
	state.AddBalance(header.Coinbase, big.NewInt(100000))
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	return types.NewBlock(header, txs, uncles, receipts), nil
}

func (s *SimplePow) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(0)
}

func (s *SimplePow) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{}
}
