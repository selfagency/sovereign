package atproto

import (
	"context"
	"fmt"
	"io"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/repo"
	"github.com/ipfs/go-blockservice"
	"github.com/ipfs/go-cid"
	// Register the dag-cbor codec (0x71) in the ipld-prime registry so
	// car.WriteCar can decode the repo's record blocks (A6). Without this,
	// WriteCAR fails with "no decoder registered for multicodec code 113".
	offline "github.com/ipfs/go-ipfs-exchange-offline"
	"github.com/ipfs/go-merkledag"
	car "github.com/ipld/go-car"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/multicodec"

	"github.com/selfagency/sovereign/internal/pdsstore"
)

// Repo wraps an atproto repository with commit signing.
type Repo struct {
	r  *repo.Repo
	sk atcrypto.PrivateKey
	bs *pdsstore.Blockstore
}

// init registers the dag-cbor codec (0x71) in the ipld-prime registry so
// car.WriteCar can decode the repo's record blocks (A6).
func init() {
	multicodec.RegisterEncoder(uint64(0x71), dagcbor.Encode)
	multicodec.RegisterDecoder(uint64(0x71), dagcbor.Decode)
}

// NewRepo creates a durable repo for a DID with the given signing key. The
// repo's MST/records/commits are persisted to a SQLite blockstore at path,
// surviving restarts. If a repo already exists at path, it is reopened.
func NewRepo(ctx context.Context, did string, sk atcrypto.PrivateKey, blockstorePath string) (*Repo, error) {
	bs, err := pdsstore.Open(blockstorePath)
	if err != nil {
		return nil, fmt.Errorf("open blockstore: %w", err)
	}
	root, err := bs.Root(ctx)
	if err != nil {
		_ = bs.Close()
		return nil, fmt.Errorf("read repo root: %w", err)
	}
	if root != "" {
		rootCid, err := cid.Decode(root)
		if err != nil {
			_ = bs.Close()
			return nil, fmt.Errorf("decode repo root: %w", err)
		}
		r, err := repo.OpenRepo(ctx, bs, rootCid)
		if err != nil {
			_ = bs.Close()
			return nil, fmt.Errorf("open existing repo: %w", err)
		}
		return &Repo{r: r, sk: sk, bs: bs}, nil
	}
	r := repo.NewRepo(ctx, did, bs)
	return &Repo{r: r, sk: sk, bs: bs}, nil
}

// Close closes the underlying blockstore.
func (r *Repo) Close() error {
	return r.bs.Close()
}

// CreateRecord writes a record to the repo and returns its CID and TID.
func (r *Repo) CreateRecord(ctx context.Context, nsid string, rec repo.CborMarshaler) (cidStr, tid string, err error) {
	c, tid, err := r.r.CreateRecord(ctx, nsid, rec)
	if err != nil {
		return "", "", err
	}
	return c.String(), tid, nil
}

// Commit signs and commits the repo, returning the commit CID and revision.
// The commit root is persisted so the repo can be reopened later.
func (r *Repo) Commit(ctx context.Context) (commitCid, rev string, err error) {
	c, rev, err := r.r.Commit(ctx, func(_ context.Context, _ string, data []byte) ([]byte, error) {
		return r.sk.HashAndSign(data)
	})
	if err != nil {
		return "", "", err
	}
	if err := r.bs.SetRoot(ctx, c.String()); err != nil {
		return "", "", fmt.Errorf("persist repo root: %w", err)
	}
	return c.String(), rev, nil
}

// SignedCommit returns the current signed commit.
func (r *Repo) SignedCommit() repo.SignedCommit {
	return r.r.SignedCommit()
}

// GetRecordBytes returns the raw CBOR bytes of a record at rpath.
func (r *Repo) GetRecordBytes(ctx context.Context, rpath string) (cidStr string, data []byte, err error) {
	c, d, err := r.r.GetRecordBytes(ctx, rpath)
	if err != nil {
		return "", nil, err
	}
	return c.String(), *d, nil
}

// WriteCAR writes the repo as a CAR (v1) to w, rooted at the persisted commit.
func (r *Repo) WriteCAR(ctx context.Context, w io.Writer) error {
	root, err := r.bs.Root(ctx)
	if err != nil {
		return fmt.Errorf("read repo root: %w", err)
	}
	if root == "" {
		return fmt.Errorf("repo has no root (nothing committed)")
	}
	rootCid, err := cid.Decode(root)
	if err != nil {
		return fmt.Errorf("decode repo root: %w", err)
	}
	// Wrap the blockstore in a DAG service so car.WriteCar can walk it.
	dag := merkledag.NewDAGService(blockservice.New(r.bs, offline.Exchange(r.bs)))
	return car.WriteCar(ctx, dag, []cid.Cid{rootCid}, w)
}

// VerifyCommit verifies the repo's signed commit against a public key.
func (r *Repo) VerifyCommit(pub atcrypto.PublicKey) error {
	sc := r.r.SignedCommit()
	signingBytes, err := sc.Unsigned().BytesForSigning()
	if err != nil {
		return fmt.Errorf("commit signing bytes: %w", err)
	}
	if err := pub.HashAndVerify(signingBytes, sc.Sig); err != nil {
		return fmt.Errorf("commit signature invalid: %w", err)
	}
	return nil
}
