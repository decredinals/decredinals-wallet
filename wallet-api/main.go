
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/txscript/v4"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/decred/dcrd/wire"
)

const (
	ATOMS_PER_DCR      = 1e8
	DEFAULT_DUST_ATOMS = int64(10000)
)

var (
	params      = chaincfg.MainNetParams()
	insightBase = strings.TrimRight(getenv("INSIGHT_BASE", "https://dcrdata.decred.org/insight/api"), "/")
	listenAddr  = ":" + getenv("PORT", "8787")
	httpClient  = &http.Client{Timeout: 12 * time.Second}
)


func getenv(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	writeJSON(w, map[string]any{"ok": false, "error": msg})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rejectSensitiveJSON(next http.Handler) http.Handler {
	badKeys := []string{
		`"seed"`, `"seedwords"`, `"mnemonic"`,
		`"wif"`, `"privatekey"`, `"privkey"`,
		`"xpriv"`, `"xprv"`,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := strings.ToLower(r.Header.Get("Content-Type"))
			if strings.Contains(ct, "application/json") {
				b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				_ = r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(b))

				low := strings.ToLower(string(b))
				for _, k := range badKeys {
					if strings.Contains(low, k) {
						writeErr(w, 400, "Sensitive fields are not allowed")
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func parseIntQ(r *http.Request, key string, def, min, max int) int {
	s := strings.TrimSpace(r.URL.Query().Get(key))
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func isFinite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }


type StatusResp struct {
	Ok          bool   `json:"ok"`
	InsightBase string `json:"insightBase"`
	Now         string `json:"now"`
}

type InsightUTXO struct {
	Txid          string  `json:"txid"`
	Vout          uint32  `json:"vout"`
	ScriptPubKey  string  `json:"scriptPubKey"`
	Satoshis      int64   `json:"satoshis"`
	Amount        float64 `json:"amount"`
	Confirmations int64   `json:"confirmations,omitempty"`
}

type UtxosResp struct {
	Ok           bool         `json:"ok"`
	Network      string       `json:"network"`
	Address      string       `json:"address"`
	UTXOs        []InsightUTXO `json:"utxos"`
	BalanceAtoms int64        `json:"balanceAtoms"`
	BalanceDcr   float64      `json:"balanceDcr"`
}

type TxsResp struct {
	Ok      bool             `json:"ok"`
	Network string           `json:"network"`
	Address string           `json:"address"`
	Skip    int              `json:"skip"`
	Count   int              `json:"count"`
	Items   []map[string]any `json:"items"`
	Raw     any              `json:"raw,omitempty"`
	Error   string           `json:"error,omitempty"`
}

type BuildTxReq struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Atoms   int64  `json:"atoms"`
	MinConf int64  `json:"minConf,omitempty"`
}

type BuildTxInput struct {
	Txid         string `json:"txid"`
	Vout         uint32 `json:"vout"`
	Atoms        int64  `json:"atoms"`
	ScriptPubKey string `json:"scriptPubKey"`
}

type BuildTxResp struct {
	Ok      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Network string `json:"network,omitempty"`

	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Atoms int64  `json:"atoms,omitempty"`

	FeeAtoms    int64 `json:"feeAtoms,omitempty"`
	ChangeAtoms int64 `json:"changeAtoms,omitempty"`

	UnsignedTxHex string         `json:"unsignedTxHex,omitempty"`
	Inputs        []BuildTxInput `json:"inputs,omitempty"`
	Note          string         `json:"note,omitempty"`
}

type SigHashReq struct {
	UnsignedTxHex string         `json:"unsignedTxHex"`
	Inputs        []BuildTxInput `json:"inputs"` 
	ScriptVersion uint16         `json:"scriptVersion,omitempty"`
}

type SigHashResp struct {
	Ok        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
	HashType  uint32   `json:"hashType,omitempty"`  
	Sighashes []string `json:"sighashes,omitempty"`
}

type FinalizeSig struct {
	Index     int    `json:"index"`
	SigDerHex string `json:"sigDerHex"`
	PubkeyHex string `json:"pubkeyHex"`
}

type FinalizeReq struct {
	UnsignedTxHex string        `json:"unsignedTxHex"`
	Sigs          []FinalizeSig `json:"sigs"`
	ScriptVersion uint16        `json:"scriptVersion,omitempty"`
}

type FinalizeResp struct {
	Ok       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	RawTxHex string `json:"rawTxHex,omitempty"`
	Txid     string `json:"txid,omitempty"`
	HashType uint32 `json:"hashType,omitempty"`
}

type BroadcastReq struct {
	RawTx string `json:"rawtx"`
}
type BroadcastResp struct {
	Ok   bool   `json:"ok"`
	Txid string `json:"txid,omitempty"`
	Err  string `json:"error,omitempty"`
}


func fetchUtxos(ctx context.Context, addr string) ([]InsightUTXO, error) {
	u := insightBase + "/addr/" + addr + "/utxo"
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("utxo http %d: %s", resp.StatusCode, string(b))
	}

	var xs []InsightUTXO
	if err := json.NewDecoder(resp.Body).Decode(&xs); err != nil {
		return nil, err
	}
	for i := range xs {
		if xs[i].Satoshis == 0 && isFinite(xs[i].Amount) && xs[i].Amount != 0 {
			xs[i].Satoshis = int64(math.Round(xs[i].Amount * ATOMS_PER_DCR))
		}
	}
	return xs, nil
}

func broadcast(ctx context.Context, rawHex string) (string, error) {
	body, _ := json.Marshal(map[string]string{"rawtx": rawHex})
	req, _ := http.NewRequestWithContext(ctx, "POST", insightBase+"/tx/send", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("broadcast http %d: %s", resp.StatusCode, string(b))
	}

	var any map[string]any
	if err := json.Unmarshal(b, &any); err == nil {
		if v, ok := any["txid"].(string); ok && v != "" {
			return v, nil
		}
		if v, ok := any["result"].(string); ok && v != "" {
			return v, nil
		}
	}
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if len(s) == 64 {
		return s, nil
	}
	return "", fmt.Errorf("broadcast unknown response: %s", string(b))
}

func fetchTxsInsight(ctx context.Context, addr string, skip int, count int) (raw any, items []map[string]any, err error) {
	from := skip
	to := skip + count
	u := fmt.Sprintf("%s/txs?address=%s&from=%d&to=%d", insightBase, url.QueryEscape(addr), from, to)

	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("txs http %d: %s", resp.StatusCode, string(b))
	}

	var j any
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, nil, err
	}
	raw = j

	m, _ := j.(map[string]any)
	if m != nil {
		if arr, ok := m["items"].([]any); ok {
			return raw, coerceItems(arr), nil
		}
		if arr, ok := m["txs"].([]any); ok {
			return raw, coerceItems(arr), nil
		}
		if arr, ok := m["transactions"].([]any); ok {
			return raw, coerceItems(arr), nil
		}
	}
	if arr, ok := j.([]any); ok {
		return raw, coerceItems(arr), nil
	}
	return raw, []map[string]any{}, nil
}

func coerceItems(arr []any) []map[string]any {
	out := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		if mm, ok := it.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}


func addrToPkScript(addr string) ([]byte, error) {
	a, err := stdaddr.DecodeAddress(strings.TrimSpace(addr), params)
	if err != nil {
		return nil, err
	}
	_, script := a.PaymentScript()
	return script, nil
}

func estimateFeeAtoms(numInputs, numOutputs int) int64 {
	base := int64(10000)
	perIn := int64(2500)
	perOut := int64(2000)
	return base + int64(numInputs)*perIn + int64(numOutputs)*perOut
}

func txToHex(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func txFromHex(txHex string) (*wire.MsgTx, error) {
	txHex = strings.TrimSpace(txHex)
	if txHex == "" {
		return nil, errors.New("empty tx hex")
	}
	raw, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, fmt.Errorf("bad tx hex: %v", err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("tx deserialize: %v", err)
	}
	return &tx, nil
}

func buildUnsignedSendTx(ctx context.Context, fromAddr, toAddr string, atoms int64, minConf int64) (BuildTxResp, error) {
	out := BuildTxResp{Ok: false, Network: "mainnet"}

	if !strings.HasPrefix(fromAddr, "D") || !strings.HasPrefix(toAddr, "D") {
		return out, errors.New("from/to must be mainnet addresses (start with D)")
	}
	if atoms <= 0 {
		return out, errors.New("atoms must be > 0")
	}
	if minConf <= 0 {
		minConf = 1
	}

	utxos, err := fetchUtxos(ctx, fromAddr)
	if err != nil {
		return out, err
	}

	cands := make([]InsightUTXO, 0, len(utxos))
	for _, u := range utxos {
		if u.Satoshis <= 0 {
			continue
		}
		if u.Confirmations < minConf {
			continue
		}
		if strings.TrimSpace(u.ScriptPubKey) == "" {
			continue
		}
		cands = append(cands, u)
	}
	if len(cands) == 0 {
		return out, errors.New("no spendable utxos (need confirmed funds)")
	}

	for i := 0; i < len(cands); i++ {
		for j := i + 1; j < len(cands); j++ {
			if cands[j].Satoshis > cands[i].Satoshis {
				cands[i], cands[j] = cands[j], cands[i]
			}
		}
	}

	tx := wire.NewMsgTx()
	tx.Version = 1

	toPk, err := addrToPkScript(toAddr)
	if err != nil {
		return out, err
	}
	tx.AddTxOut(wire.NewTxOut(atoms, toPk))

	var selected []InsightUTXO
	var totalIn int64

	for _, u := range cands {
		h, err := chainhash.NewHashFromStr(u.Txid)
		if err != nil {
			continue
		}

		op := wire.NewOutPoint(h, u.Vout, wire.TxTreeRegular)
		in := wire.NewTxIn(op, u.Satoshis, nil)
		in.BlockHeight = wire.NullBlockHeight
		in.BlockIndex = wire.NullBlockIndex
		tx.AddTxIn(in)

		selected = append(selected, u)
		totalIn += u.Satoshis

		fee := estimateFeeAtoms(len(selected), 2)
		if totalIn >= atoms+fee {
			break
		}
	}

	fee := estimateFeeAtoms(len(selected), 2)
	if totalIn < atoms+fee {
		return out, fmt.Errorf("insufficient funds: have %d atoms, need %d atoms", totalIn, atoms+fee)
	}

	change := totalIn - atoms - fee
	if change > 0 {
		if change < DEFAULT_DUST_ATOMS {
			fee += change
			change = 0
		} else {
			changePk, err := addrToPkScript(fromAddr)
			if err != nil {
				return out, err
			}
			tx.AddTxOut(wire.NewTxOut(change, changePk))
		}
	}

	unsignedHex, err := txToHex(tx)
	if err != nil {
		return out, err
	}

	inputs := make([]BuildTxInput, 0, len(selected))
	for _, u := range selected {
		inputs = append(inputs, BuildTxInput{
			Txid: u.Txid, Vout: u.Vout, Atoms: u.Satoshis, ScriptPubKey: strings.TrimSpace(u.ScriptPubKey),
		})
	}

	out.Ok = true
	out.From = fromAddr
	out.To = toAddr
	out.Atoms = atoms
	out.FeeAtoms = fee
	out.ChangeAtoms = change
	out.UnsignedTxHex = unsignedHex
	out.Inputs = inputs
	out.Note = "Unsigned regular tx. Client signs each input (P2PKH SigHashAll) using prevout scriptPubKey, then finalize + broadcast."
	return out, nil
}


func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, StatusResp{
			Ok:          true,
			InsightBase: insightBase,
			Now:         time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/utxos/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, 405, "GET only")
			return
		}
		addr := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/utxos/"))
		if addr == "" {
			writeErr(w, 400, "address required")
			return
		}
		if !strings.HasPrefix(addr, "D") {
			writeJSON(w, map[string]any{"ok": false, "error": "Not mainnet address (must start with D)", "network": "mainnet", "address": addr})
			return
		}

		utxos, err := fetchUtxos(r.Context(), addr)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}

		var bal int64
		for _, u := range utxos {
			bal += u.Satoshis
		}

		writeJSON(w, UtxosResp{
			Ok:           true,
			Network:      "mainnet",
			Address:      addr,
			UTXOs:        utxos,
			BalanceAtoms: bal,
			BalanceDcr:   float64(bal) / ATOMS_PER_DCR,
		})
	})

	mux.HandleFunc("/api/txs/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, 405, "GET only")
			return
		}
		addr := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/txs/"))
		if addr == "" {
			writeErr(w, 400, "address required")
			return
		}
		if !strings.HasPrefix(addr, "D") {
			writeJSON(w, TxsResp{Ok: false, Error: "Not mainnet address (must start with D)", Network: "mainnet", Address: addr})
			return
		}

		skip := parseIntQ(r, "skip", 0, 0, 1_000_000)
		count := parseIntQ(r, "count", 20, 1, 100)

		raw, items, err := fetchTxsInsight(r.Context(), addr, skip, count)
		if err != nil {
			writeJSON(w, TxsResp{Ok: false, Error: err.Error(), Network: "mainnet", Address: addr, Skip: skip, Count: count})
			return
		}

		writeJSON(w, TxsResp{
			Ok:      true,
			Network: "mainnet",
			Address: addr,
			Skip:    skip,
			Count:   count,
			Items:   items,
			Raw:     raw,
		})
	})

	mux.HandleFunc("/api/tx/build", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "POST only")
			return
		}
		var req BuildTxReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			writeErr(w, 400, "bad json: "+err.Error())
			return
		}
		req.From = strings.TrimSpace(req.From)
		req.To = strings.TrimSpace(req.To)

		resp, err := buildUnsignedSendTx(r.Context(), req.From, req.To, req.Atoms, req.MinConf)
		if err != nil {
			resp.Ok = false
			resp.Error = err.Error()
			writeJSON(w, resp)
			return
		}
		writeJSON(w, resp)
	})

	mux.HandleFunc("/api/tx/sighash", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "POST only")
			return
		}

		var req SigHashReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
			writeErr(w, 400, "bad json: "+err.Error())
			return
		}
		if strings.TrimSpace(req.UnsignedTxHex) == "" {
			writeJSON(w, SigHashResp{Ok: false, Error: "unsignedTxHex required"})
			return
		}

		tx, err := txFromHex(req.UnsignedTxHex)
		if err != nil {
			writeJSON(w, SigHashResp{Ok: false, Error: err.Error()})
			return
		}
		if len(req.Inputs) != len(tx.TxIn) {
			writeJSON(w, SigHashResp{Ok: false, Error: fmt.Sprintf("inputs mismatch: got %d, tx has %d inputs", len(req.Inputs), len(tx.TxIn))})
			return
		}

		hashType := txscript.SigHashAll
		_ = req.ScriptVersion

		sighashes := make([]string, 0, len(tx.TxIn))
		for i := 0; i < len(tx.TxIn); i++ {
			pkHex := strings.TrimSpace(req.Inputs[i].ScriptPubKey)
			if pkHex == "" {
				writeJSON(w, SigHashResp{Ok: false, Error: fmt.Sprintf("missing scriptPubKey for input %d", i)})
				return
			}
			pkScript, err := hex.DecodeString(pkHex)
			if err != nil {
				writeJSON(w, SigHashResp{Ok: false, Error: fmt.Sprintf("bad scriptPubKey hex for input %d: %v", i, err)})
				return
			}

			h, err := txscript.CalcSignatureHash(pkScript, hashType, tx, i, nil)
			if err != nil {
				writeJSON(w, SigHashResp{Ok: false, Error: fmt.Sprintf("CalcSignatureHash input %d: %v", i, err)})
				return
			}
			sighashes = append(sighashes, hex.EncodeToString(h[:]))
		}

		writeJSON(w, SigHashResp{
			Ok:        true,
			HashType:  uint32(hashType),
			Sighashes: sighashes,
		})
	})

	mux.HandleFunc("/api/tx/finalize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "POST only")
			return
		}

		var req FinalizeReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
			writeErr(w, 400, "bad json: "+err.Error())
			return
		}
		if strings.TrimSpace(req.UnsignedTxHex) == "" {
			writeJSON(w, FinalizeResp{Ok: false, Error: "unsignedTxHex required"})
			return
		}

		tx, err := txFromHex(req.UnsignedTxHex)
		if err != nil {
			writeJSON(w, FinalizeResp{Ok: false, Error: err.Error()})
			return
		}

		hashType := txscript.SigHashAll
		hashTypeByte := byte(hashType)

		for _, s := range req.Sigs {
			if s.Index < 0 || s.Index >= len(tx.TxIn) {
				writeJSON(w, FinalizeResp{Ok: false, Error: fmt.Sprintf("sig index out of range: %d", s.Index)})
				return
			}
			sigDer, err := hex.DecodeString(strings.TrimSpace(s.SigDerHex))
			if err != nil {
				writeJSON(w, FinalizeResp{Ok: false, Error: fmt.Sprintf("bad sigDerHex for input %d: %v", s.Index, err)})
				return
			}
			pub, err := hex.DecodeString(strings.TrimSpace(s.PubkeyHex))
			if err != nil {
				writeJSON(w, FinalizeResp{Ok: false, Error: fmt.Sprintf("bad pubkeyHex for input %d: %v", s.Index, err)})
				return
			}
			if len(pub) != 33 {
				writeJSON(w, FinalizeResp{Ok: false, Error: fmt.Sprintf("pubkey must be compressed 33 bytes for input %d", s.Index)})
				return
			}

			sigWithHashType := append(sigDer, hashTypeByte)

			scriptSig, err := txscript.NewScriptBuilder().
				AddData(sigWithHashType).
				AddData(pub).
				Script()
			if err != nil {
				writeJSON(w, FinalizeResp{Ok: false, Error: fmt.Sprintf("build scriptSig for input %d: %v", s.Index, err)})
				return
			}

			tx.TxIn[s.Index].SignatureScript = scriptSig
		}

		rawHex, err := txToHex(tx)
		if err != nil {
			writeJSON(w, FinalizeResp{Ok: false, Error: err.Error()})
			return
		}

		txid := tx.TxHash().String()

		writeJSON(w, FinalizeResp{
			Ok:       true,
			RawTxHex: rawHex,
			Txid:     txid,
			HashType: uint32(hashType),
		})
	})

	mux.HandleFunc("/api/tx/broadcast", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "POST only")
			return
		}
		var req BroadcastReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
			writeErr(w, 400, "bad json: "+err.Error())
			return
		}
		raw := strings.TrimSpace(req.RawTx)
		if raw == "" {
			writeErr(w, 400, "rawtx is required")
			return
		}

		txid, err := broadcast(r.Context(), raw)
		if err != nil {
			writeJSON(w, BroadcastResp{Ok: false, Err: err.Error()})
			return
		}
		writeJSON(w, BroadcastResp{Ok: true, Txid: txid})
	})

	handler := withCORS(rejectSensitiveJSON(mux))

	srv := &http.Server{Addr: listenAddr, Handler: handler}
	fmt.Println("[relay] listening on", listenAddr)
	fmt.Println("[relay] insightBase =", insightBase)
	_ = srv.ListenAndServe()
}
