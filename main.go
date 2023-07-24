package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// Define the template data context
type TemplateContext struct {
	NodeAddress string
	Posts       []Posts
	Title       string
}

const ConnectedNodeAddress = "http://localhost:8080"

// Block represents a block in the blockchain.
type Block struct {
	Index        int64         `json:"index"`
	Transactions []Transaction `json:"transactions"`
	Timestamp    int64         `json:"timestamp"`
	Data         interface{}
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
	Nonce        int64  `json:"nonce"`
}

// Transaction represents a basic transaction in the blockchain.
type Transaction struct {
	ID       string  `json:"id"`
	Sender   string  `json:"sender"`
	Receiver string  `json:"receiver"`
	Amount   float64 `json:"amount"`
} // Define a struct to hold the post data
type Posts struct {
	Author    string
	Content   string
	Timestamp int64
}
type Post struct {
	Index     int64  `json:"index"`
	Hash      string `json:"hash"`
	Timestamp int64  `json:"timestamp"`
	// Add other fields based on your transaction structure
	// For example:
	// Title   string `json:"title"`
	// Content string `json:"content"`
}

var posts []Post

// Blockchain represents a chain of blocks.
type Blockchain struct {
	unconfirmedTransactions []Transaction
	Chain                   []*Block
	mu                      sync.Mutex
}

func NewBlockchain() *Blockchain {
	blockchain := &Blockchain{}
	blockchain.createGenesisBlock()
	return blockchain
}

func (bc *Blockchain) createGenesisBlock() {
	genesisBlock := NewBlock(0, []Transaction{}, time.Now().Unix(), "0")
	proof := genesisBlock.proofOfWork()
	bc.addBlock(genesisBlock, proof)
}

func (bc *Blockchain) mine() int64 {
	if len(bc.unconfirmedTransactions) == 0 {
		return -1
	}

	lastBlock := bc.lastBlock()

	newBlock := NewBlock(lastBlock.Index+1, bc.unconfirmedTransactions, time.Now().Unix(), lastBlock.Hash)

	proof := newBlock.proofOfWork()
	bc.addBlock(newBlock, proof)
	bc.unconfirmedTransactions = nil
	return newBlock.Index
}

func (bc *Blockchain) lastBlock() *Block {
	if len(bc.Chain) > 0 {
		return bc.Chain[len(bc.Chain)-1]
	}
	return nil
}
func (bc *Blockchain) addBlock(block *Block, proof int64) {
	block.Nonce = proof
	blockHash := calculateBlockHash(block)
	block.Hash = blockHash
	bc.Chain = append(bc.Chain, block)
}
func calculateBlockHash(block *Block) string {
	data := strconv.FormatInt(block.Index, 10) + strconv.FormatInt(block.Timestamp, 10) + block.PreviousHash + strconv.FormatInt(block.Nonce, 10)

	// Include transactions in the data to calculate hash
	for _, tx := range block.Transactions {
		data += tx.ID + tx.Sender + tx.Receiver + strconv.FormatFloat(tx.Amount, 'f', -1, 64)
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (bc *Blockchain) addNewTransaction(transaction Transaction) {
	bc.unconfirmedTransactions = append(bc.unconfirmedTransactions, transaction)
}

func (bc *Blockchain) LastBlock() *Block {
	if len(bc.Chain) > 0 {
		return bc.Chain[len(bc.Chain)-1]
	}
	return nil
}

const Difficulty = 2

func (b *Block) proofOfWork() int64 {
	targetPrefix := strings.Repeat("0", int(Difficulty))
	var nonce int64
	for {
		data := strconv.FormatInt(b.Index, 10) + strconv.FormatInt(b.Timestamp, 10) + b.PreviousHash + strconv.FormatInt(nonce, 10)

		// Include transactions in the data to calculate hash
		for _, tx := range b.Transactions {
			data += tx.ID + tx.Sender + tx.Receiver + fmt.Sprintf("%.2f", tx.Amount)
		}

		hash := sha256.Sum256([]byte(data))
		hashString := hex.EncodeToString(hash[:])

		if strings.HasPrefix(hashString, targetPrefix) {
			b.Hash = hashString
			b.Nonce = nonce
			return nonce
		}

		nonce++
	}
}

func NewBlock(index int64, transactions []Transaction, timestamp int64, previousHash string) *Block {
	block := &Block{
		Index:        index,
		Transactions: transactions,
		Timestamp:    timestamp,
		PreviousHash: previousHash,
	}

	// Calculate the hash and nonce for the block using the proof of work function
	block.proofOfWork()

	return block
}
func NewTransactionHandler(w http.ResponseWriter, r *http.Request, blockchain *Blockchain) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Decode the JSON data from the request body
	var txData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&txData); err != nil {
		http.Error(w, "Failed to decode JSON data", http.StatusBadRequest)
		return
	}

	// Check for required fields in the JSON data
	requiredFields := []string{"author", "content"}
	for _, field := range requiredFields {
		if _, ok := txData[field]; !ok {
			http.Error(w, fmt.Sprintf("Invalid transaction data: missing field '%s'", field), http.StatusBadRequest)
			return
		}
	}

	// Add a timestamp to the transaction data
	txData["timestamp"] = time.Now().Unix()

	// Convert the txData to a slice of Transaction
	transaction := Transaction{
		ID:       fmt.Sprintf("%v", txData["id"]),
		Sender:   fmt.Sprintf("%v", txData["sender"]),
		Receiver: fmt.Sprintf("%v", txData["receiver"]),
		Amount:   txData["amount"].(float64), // Assuming amount is a float64 in JSON
	}

	// Add the new transaction to the blockchain
	blockchain.addNewTransaction(transaction)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, "Success")
}

func GetChainHandler(w http.ResponseWriter, r *http.Request, blockchain *Blockchain) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	chainData := make([]map[string]interface{}, len(blockchain.Chain))
	for i, block := range blockchain.Chain {
		chainData[i] = map[string]interface{}{
			"index":         block.Index,
			"transactions":  block.Transactions,
			"timestamp":     block.Timestamp,
			"data":          block.Data,
			"previous_hash": block.PreviousHash,
			"hash":          block.Hash,
			"nonce":         block.Nonce,
		}
	}

	responseData := map[string]interface{}{
		"length": len(chainData),
		"chain":  chainData,
	}

	// Set the Content-Type header to application/json
	w.Header().Set("Content-Type", "application/json")

	// Convert the responseData to JSON format and write it to the response
	if err := json.NewEncoder(w).Encode(responseData); err != nil {
		http.Error(w, "Failed to encode response data", http.StatusInternalServerError)
		return
	}
}

func MineUnconfirmedTransactionsHandler(w http.ResponseWriter, r *http.Request, blockchain *Blockchain) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	result := blockchain.mine()
	if result == -1 {
		fmt.Fprint(w, "No transactions to mine")
		return
	}

	fmt.Fprintf(w, "Block #%d is mined.", result)
}

func GetPendingTxHandler(w http.ResponseWriter, r *http.Request, blockchain *Blockchain) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Set the Content-Type header to application/json
	w.Header().Set("Content-Type", "application/json")

	// Convert the unconfirmed_transactions to JSON format and write it to the response
	if err := json.NewEncoder(w).Encode(blockchain.unconfirmedTransactions); err != nil {
		http.Error(w, "Failed to encode response data", http.StatusInternalServerError)
		return
	}
}

var (
	peers = make(map[string]struct{})
	mu    sync.RWMutex // Mutex to protect concurrent access to peers
)

func RegisterNewPeersHandler(w http.ResponseWriter, r *http.Request, blockchain *Blockchain) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		NodeAddress string `json:"node_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	if data.NodeAddress == "" {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	peers[data.NodeAddress] = struct{}{}

	// Return the blockchain to the newly registered node so that it can sync
	GetChainHandler(w, r, blockchain)
}

func createChainFromDump(chainDump []map[string]interface{}) *Blockchain {
	blockchain := NewBlockchain()
	for _, blockData := range chainDump {
		block := NewBlock(
			int64(blockData["index"].(float64)),
			unmarshalTransactions(blockData["transactions"]),
			int64(blockData["timestamp"].(float64)),
			blockData["previous_hash"].(string),
		)
		block.Hash = blockData["hash"].(string)
		block.Nonce = int64(blockData["nonce"].(float64))

		genesisBlock := NewBlock(0, []Transaction{}, time.Now().Unix(), "0")
		proof := genesisBlock.proofOfWork()
		blockchain.addBlock(block, proof)
	}
	return blockchain
}

func unmarshalTransactions(txs interface{}) []Transaction {
	var transactions []Transaction
	data, err := json.Marshal(txs)
	if err != nil {
		return transactions
	}
	err = json.Unmarshal(data, &transactions)
	if err != nil {
		return transactions
	}
	return transactions
}

func RegisterWithExistingNodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var data struct {
		NodeAddress string `json:"node_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	if data.NodeAddress == "" {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	registerData := map[string]string{
		"node_address": r.Host,
	}
	registerDataJSON, _ := json.Marshal(registerData)

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")

	resp, err := http.Post(data.NodeAddress+"/register_node", "application/json", bytes.NewBuffer(registerDataJSON))
	if err != nil {
		http.Error(w, "Failed to register with remote node", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		mu.Lock()
		defer mu.Unlock()
		// Update chain and peers
		var responseData struct {
			Chain []map[string]interface{} `json:"chain"`
			Peers []string                 `json:"peers"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			http.Error(w, "Failed to decode response data", http.StatusInternalServerError)
			return
		}
		blockchain := createChainFromDump(responseData.Chain)
		for _, peer := range responseData.Peers {
			peers[peer] = struct{}{}
		}

		fmt.Fprint(w, "Registration successful", blockchain)
	} else {
		// If something goes wrong, pass it on to the API response
		http.Error(w, "Registration failed", resp.StatusCode)
	}
}

// ... (rest of the code remains unchanged)

// isBlockValidProof is a helper method to check if a given block's proof is valid.
func (bc *Blockchain) isBlockValidProof(block *Block, blockHash string) bool {
	targetPrefix := strings.Repeat("0", int(Difficulty))
	data := strconv.FormatInt(block.Index, 10) + strconv.FormatInt(block.Timestamp, 10) + block.PreviousHash + strconv.FormatInt(block.Nonce, 10)

	// Include transactions in the data to calculate hash
	for _, tx := range block.Transactions {
		data += tx.ID + tx.Sender + tx.Receiver + fmt.Sprintf("%.2f", tx.Amount)
	}

	hash := sha256.Sum256([]byte(data))
	hashString := hex.EncodeToString(hash[:])

	return hashString == blockHash && strings.HasPrefix(hashString, targetPrefix)
}

// CheckChainValidity is a helper method to check if the entire blockchain is valid.
func (bc *Blockchain) CheckChainValidity(chain []*Block) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	result := true
	previousHash := "0"

	// Iterate through every block
	for _, block := range chain {
		blockHash := block.Hash
		// Remove the hash field to recompute the hash again using `ProofOfWork` method.
		block.Hash = ""

		if !bc.isBlockValidProof(block, blockHash) || previousHash != block.PreviousHash {
			result = false
			break
		}

		block.Hash, previousHash = blockHash, blockHash
	}

	return result
}

// Consensus is our simple consensus algorithm.
// If a longer valid chain is found, our chain is replaced with it.
func (bc *Blockchain) Consensus() bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	longestChain := bc.Chain
	currentLen := len(bc.Chain)

	for node := range peers {
		response, err := http.Get(fmt.Sprintf("%s/chain", node))
		if err != nil {
			continue
		}

		var responseData struct {
			Length int64    `json:"length"`
			Chain  []*Block `json:"chain"`
		}

		if err := json.NewDecoder(response.Body).Decode(&responseData); err != nil {
			continue
		}

		response.Body.Close()

		if responseData.Length > int64(currentLen) && bc.CheckChainValidity(responseData.Chain) {
			// Longer valid chain found!
			currentLen = int(responseData.Length)
			longestChain = responseData.Chain
		}
	}

	if longestChain != nil && len(longestChain) > 0 {
		bc.Chain = longestChain
		return true
	}

	return false
}

func VerifyAndAddBlockHandler(w http.ResponseWriter, r *http.Request, blockchain *Blockchain) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var blockData struct {
		Index        int64         `json:"index"`
		Transactions []Transaction `json:"transactions"`
		Timestamp    int64         `json:"timestamp"`
		PreviousHash string        `json:"previous_hash"`
	}

	if err := json.NewDecoder(r.Body).Decode(&blockData); err != nil {
		http.Error(w, "Invalid block data", http.StatusBadRequest)
		return
	}

	block := NewBlock(blockData.Index, blockData.Transactions, blockData.Timestamp, blockData.PreviousHash)
	proof := block.proofOfWork()
	//added := blockchain.addBlock(block, proof)
	/* if !added {
		http.Error(w, "The block was discarded by the node", http.StatusBadRequest)
		return
	} */

	fmt.Fprint(w, "Block added to the chain", proof)
}

func AnnounceNewBlock(block *Block) {
	mu.Lock()
	defer mu.Unlock()

	blockJSON, err := json.Marshal(block)
	if err != nil {
		fmt.Println("Error marshaling block to JSON")
		return
	}

	for peer := range peers {
		url := fmt.Sprintf("%s/add_block", peer)
		_, err := http.Post(url, "application/json", bytes.NewBuffer(blockJSON))
		if err != nil {
			fmt.Printf("Failed to announce new block to %s: %v\n", peer, err)
		}
	}
}
func handleHomePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Make a GET request to the connected node's API endpoint
	response, err := http.Get(ConnectedNodeAddress + "/chain")
	if err != nil {
		http.Error(w, "Error fetching blockchain data", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		var data map[string]interface{}
		err := json.NewDecoder(response.Body).Decode(&data)
		if err != nil {
			http.Error(w, "Error parsing blockchain data", http.StatusInternalServerError)
			return
		}

		chainLength := int(data["length"].(float64))
		chainData := data["chain"].([]interface{})
		chain := make([]map[string]interface{}, chainLength)

		for i, blockData := range chainData {
			chain[i] = blockData.(map[string]interface{})
		}

		// Pass the blockchain data to the template
		renderTemplate(w, chain)
	} else {
		http.Error(w, "Error fetching blockchain data", http.StatusInternalServerError)
		return
	}
}

func renderTemplate(w http.ResponseWriter, chain []map[string]interface{}) {
	// Create your template HTML here or use a template engine like html/template.
	// Here's a basic example using fmt.Fprintf to write HTML to the response.
	// Replace this with your actual template code.
	fmt.Fprintf(w, "<html><body><h1>Blockchain Data</h1>")
	for _, block := range chain {
		blockJSON, _ := json.MarshalIndent(block, "", "  ")
		fmt.Fprintf(w, "<pre>%s</pre>", string(blockJSON))
	}
	fmt.Fprintf(w, "</body></html>")
}

func fetchPosts() {
	getChainAddress := fmt.Sprintf("%s/chain", ConnectedNodeAddress)
	response, err := http.Get(getChainAddress)
	if err != nil {
		fmt.Println("Error fetching chain data:", err)
		return
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		var chainData map[string]interface{}
		err := json.NewDecoder(response.Body).Decode(&chainData)
		if err != nil {
			fmt.Println("Error parsing chain data:", err)
			return
		}

		content := make([]Post, 0)
		chain := chainData["chain"].([]interface{})
		for _, blockData := range chain {
			block := blockData.(map[string]interface{})
			transactions := block["transactions"].([]interface{})
			for _, txData := range transactions {
				tx := txData.(map[string]interface{})
				post := Post{
					Index:     int64(block["index"].(float64)),
					Hash:      block["previous_hash"].(string),
					Timestamp: int64(tx["timestamp"].(float64)),
					// Add other fields based on your transaction structure
					// For example:
					// Title:   tx["title"].(string),
					// Content: tx["content"].(string),
				}
				content = append(content, post)
			}
		}

		sort.SliceStable(content, func(i, j int) bool {
			return content[i].Timestamp > content[j].Timestamp
		})

		// Update the global posts variable
		posts = content
	} else {
		fmt.Println("Error fetching chain data:", response.Status)
		return
	}
}

func submitTextareaHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	// Get the values from the form
	postContent := r.FormValue("content")
	author := r.FormValue("author")
	fmt.Print("postContent", postContent)
	fmt.Print("author", author)
	// Create a map for the post object
	postObject := map[string]interface{}{
		"author":  author,
		"content": postContent,
	}

	// Convert the postObject to JSON format
	postData, err := json.Marshal(postObject)
	if err != nil {
		http.Error(w, "Error marshaling JSON data", http.StatusInternalServerError)
		return
	}
	fmt.Print("postData", postData)

	// Send the JSON data as a POST request to "/new_transaction" endpoint
	newTxAddress := fmt.Sprintf("%s/new_transaction", ConnectedNodeAddress)
	resp, err := http.Post(newTxAddress, "application/json", bytes.NewBuffer(postData))

	if err != nil {
		http.Error(w, "Error sending transaction data", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		http.Error(w, "Failed to create new transaction", http.StatusInternalServerError)
		return
	}

	// Redirect to the homepage
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

//htmml work

func homepageHandler(w http.ResponseWriter, r *http.Request) {
	// Sample data for demonstration purposes
	nodeAddress := "http://localhost:8080"
	posts := []Posts{
		{
			Author:    "Alice",
			Content:   "Hello, world!",
			Timestamp: 1630767600, // Example timestamp
		},
		{
			Author:    "Bob",
			Content:   "Welcome to Go!",
			Timestamp: 1630768000, // Example timestamp
		},
	}

	// Create the template context
	context := TemplateContext{
		NodeAddress: nodeAddress,
		Title:       "Blockchain App",
		Posts:       posts,
	}

	// Parse the template
	tmpl, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}
	fmt.Print("html template", htmlTemplate)

	// Execute the template with the context
	err = tmpl.Execute(w, context)
	if err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		return
	}

	// Parse the base template
	tmplBase, err := template.New("base").Parse(baseHTML)
	if err != nil {
		fmt.Println("Error parsing base template:", err)
		http.Error(w, "Error parsing base template", http.StatusInternalServerError)
		return
	}

	// Parse the content template
	tmplContent, err := template.Must(tmplBase.Clone()).Parse(contentHTML)
	if err != nil {
		http.Error(w, "Error parsing content template", http.StatusInternalServerError)
		return
	}

	// Execute the content template with the context
	err = tmplContent.Execute(w, context)
	if err != nil {
		http.Error(w, "Error executing content template", http.StatusInternalServerError)
		return
	}
}

// Sample HTML template
const htmlTemplate = `
<!-- extend base layout -->
{{ define "base" }}
<!DOCTYPE html>
<html>
<head>
	<title>Blockchain App</title>
</head>
<body>
	<h1>Welcome to Blockchain App</h1>
	{{ template "content" . }}
</body>
</html>
{{ end }}

{{ define "content" }}
<br>
<center>
	<form action="/submit" id="textform" method="Posts">
	    <textarea name="content" rows="4" cols="50" placeholder="Just write whatever you want to..."></textarea>
	    <br>
	    <input type="text" name="author" placeholder="Your name">
	    <input type="submit" value="Posts">
	</form>
</center>

<br>
<h1>{{ .NodeAddress }}</h1>
<a href="{{ .NodeAddress }}/mine" target="_blank"><button>Request to mine</button></a>
<a href="/"><button>Resync</button></a>

<div style="margin: 20px;">

{{ range .Posts }}
<div class="post_box">
   <div class="post_box-header">
      <div class="post_box-options"><button class="option-btn">Reply</button></div>
      <div style="background: rgb(0, 97, 146) none repeat scroll 0% 0%; box-shadow: rgb(0, 97, 146) 0px 0px 0px 2px;" class="post_box-avatar">{{ .Author }}</div>
      <div class="name-header">{{ .Author }}</div>
      <div class="post_box-subtitle"> Posted at <i>{{ .Timestamp }}</i></div>
   </div>
   <div>
      <div class="post_box-body">
         <p>{{ .Content }}</p>
      </div>
   </div>
</div>
{{ end }}

<style>
	.post_box {
	    background: #fff;
	    padding: 12px 0px 0px 12px;
	    margin-top: 0px;
	    margin-bottom: 8px;
	    border-top: 1px solid #f0f0f0;
	}

	.post_box-header {
	    padding-bottom: 12px;
	}

	.post_box-avatar {
	    width: 38px;
	    height: 38px;
	    border-radius: 50%;
	    display: flex;
	    justify-content: center;
	    align-items: center;
	    color: white;
	    font-size: 22px;
	    float: left;
	    margin-right: 16px;
	    border: 1px solid #fff;
	    box-shadow: 0px 0px 0px 2px #f00;
	}

	.post_box-avatar::after {
	    content:"";
	    display:block;
	}

	.post_box-name {
	    font-weight: bold;
	}

	.post_box-subtitle {
	    color: #777;
	}

	.post_box-body {
	    margin-top: 16px;
	    margin-bottom: 8px;
	}

	.post_box-options {
	    float: right;
	}
	.option-btn {
	    background: #f8f8f8;
	    border: none;
	    color: #2c3e50;
	    padding: 7px;
	    cursor: pointer;
	    font-size: 14px;
	    margin-left: 2px;
	    margin-right: 2px;
	    outline: none;
	    height: 42px;
	}
</style>
</div>
{{ end }}
`

// Sample HTML base template
const baseHTML = `
<!DOCTYPE html>
<html>
<head>
	<title>{{ .Title }}</title>
</head>
<body>
	<div><a href="/index">Home</a></div>
	<center><h1>{{ .Title }}</h1></center>
	<hr>
	{{ with .Posts }}
		{{ if . }}
			<ul>
				{{ range . }}
					<li>Author: {{ .Author }}, Content: {{ .Content }}</li>
				{{ end }}
			</ul>
		{{ else }}
			<p>No posts available.</p>
		{{ end }}
	{{ end }}
	{{ block "content" . }}
	{{ end }}
</body>
</html>


`

// Sample HTML content template
const contentHTML = `
<br>
<center>
	<form action="/submit" id="textform" method="post">
	    <textarea name="content" rows="4" cols="50" placeholder="Just write whatever you want to..."></textarea>
	    <br>
	    <input type="text" name="author" placeholder="Your name">
	    <input type="submit" value="Posts">
	</form>
</center>

<br>

<a href="{{ .NodeAddress }}/mine" target="_blank"><button>Request to mine</button></a>
<a href="/"><button>Resync</button></a>

<div style="margin: 20px;">
{{ range .Posts }}
<div class="post_box">
   <div class="post_box-header">
      <div class="post_box-options"><button class="option-btn">Reply</button></div>
      <div style="background: rgb(0, 97, 146) none repeat scroll 0% 0%; box-shadow: rgb(0, 97, 146) 0px 0px 0px 2px;" class="post_box-avatar">{{ .Author }}</div>
      <div class="name-header">{{ .Author }}</div>
      <div class="post_box-subtitle"> Posted at <i>{{ .Timestamp }}</i></div>
   </div>
   <div>
      <div class="post_box-body">
         <p>{{ .Content }}</p>
      </div>
   </div>
</div>
{{ end }}
<style>
	.post_box {
	    background: #fff;
	    padding: 12px 0px 0px 12px;
	    margin-top: 0px;
	    margin-bottom: 8px;
	    border-top: 1px solid #f0f0f0;
	}
	
	/* Rest of the styles ... */

</style>
</div>
`

func main() {
	// Create the blockchain instance
	blockchain := NewBlockchain()

	fetchPosts()
	fmt.Println(posts)

	// Get the current timestamp
	timestamp := time.Now().Unix()
	fmt.Println("timestamp", timestamp)

	// Initialize the router using mux
	router := mux.NewRouter()
	router.HandleFunc("/", homepageHandler)
	router.HandleFunc("/mine", func(w http.ResponseWriter, r *http.Request) {
		MineUnconfirmedTransactionsHandler(w, r, blockchain)
	}).Methods("GET")

	router.HandleFunc("/submit", submitTextareaHandler)
	// Create the blockchain instance
	// Define the route to handle mining and adding new transactions
	router.HandleFunc("/mine", func(w http.ResponseWriter, r *http.Request) {
		// Example usage:
		transactions := []Transaction{
			{
				ID:       "tx1",
				Sender:   "Alice",
				Receiver: "Bob",
				Amount:   1.5,
			},
			{
				ID:       "tx2",
				Sender:   "Bob",
				Receiver: "Charlie",
				Amount:   3.0,
			},
		}

		//	http.HandleFunc("/", handleHomePage)

		// Get the hash of the last block in the chain
		previousHash := blockchain.LastBlock().Hash // The hash of the last block in the chain
		fmt.Println("previousHash", previousHash)
		block := NewBlock(1, transactions, timestamp, previousHash)
		fmt.Println("block", block)
		proof := block.proofOfWork()
		fmt.Println("proof", proof)
		blockchain.addBlock(block, proof)

		// Respond with the new block details in JSON format
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(block)

	}).Methods("GET")

	router.HandleFunc("/chain", homepageHandler)

	// Initialize the HTTP server
	router.HandleFunc("/new_transaction", func(w http.ResponseWriter, r *http.Request) {
		NewTransactionHandler(w, r, blockchain)

	})

	router.HandleFunc("/pending_tx", func(w http.ResponseWriter, r *http.Request) {
		GetPendingTxHandler(w, r, blockchain)
	})
	router.HandleFunc("/register_node", func(w http.ResponseWriter, r *http.Request) {
		RegisterNewPeersHandler(w, r, blockchain)
	})

	router.HandleFunc("/register_with", func(w http.ResponseWriter, r *http.Request) {
		RegisterWithExistingNodeHandler(w, r)
	})
	// Start the HTTP server
	fmt.Println("Listening on http://localhost:8080")
	http.ListenAndServe(":8080", router)
}
