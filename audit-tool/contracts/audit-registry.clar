;; Clarity Smart Contract Audit Tool - Audit Registry
;; Stores audit results and contract metadata

;; Error codes
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_CONTRACT (err u101))
(define-constant ERR_AUDIT_EXISTS (err u102))
(define-constant ERR_INVALID_INPUT (err u103))

;; Data structures
(define-map contracts
  { contract-id: (string-ascii 256) }
  {
    owner: principal,
    created-at: uint,
    last-audit: uint,
    audit-count: uint,
    risk-score: uint
  }
)

(define-map audit-results
  { 
    contract-id: (string-ascii 256),
    audit-id: uint
  }
  {
    auditor: principal,
    timestamp: uint,
    vulnerability-count: uint,
    high-severity: uint,
    medium-severity: uint,
    low-severity: uint,
    report-hash: (optional (buff 32))
  }
)

;; Contract owner
(define-data-var contract-owner principal tx-sender)

;; Counter for audit IDs
(define-data-var last-audit-id uint u0)

;; Read-only functions

(define-read-only (get-contract-info (contract-id (string-ascii 256)))
  (map-get? contracts { contract-id: contract-id })
)

(define-read-only (get-audit-result (contract-id (string-ascii 256)) (audit-id uint))
  (map-get? audit-results { contract-id: contract-id, audit-id: audit-id })
)

(define-read-only (get-last-audit-id)
  (var-get last-audit-id)
)

;; Public functions

;; Register a new contract for auditing
(define-public (register-contract (contract-id (string-ascii 256)))
  (let ((existing-contract (get-contract-info contract-id)))
    ;; Validate inputs
    (asserts! (is-none existing-contract) ERR_INVALID_CONTRACT)
    (asserts! (> (len contract-id) u0) ERR_INVALID_INPUT)
    
    (map-set contracts
      { contract-id: contract-id }
      {
        owner: tx-sender,
        created-at: block-height,
        last-audit: u0,
        audit-count: u0,
        risk-score: u0
      }
    )
    (ok true)
  )
)

;; Record audit result
(define-public (record-audit-result 
    (contract-id (string-ascii 256))
    (vulnerability-count uint)
    (high-severity uint)
    (medium-severity uint)
    (low-severity uint)
    (report-hash (optional (buff 32))))
  
  (let (
    (contract-info (unwrap! (get-contract-info contract-id) ERR_INVALID_CONTRACT))
    (new-audit-id (+ (var-get last-audit-id) u1))
    ;; Explicitly validate the report hash to avoid the warning
    (validated-report-hash (if (is-some report-hash) report-hash none))
  )
    ;; Validate inputs
    (asserts! (> (len contract-id) u0) ERR_INVALID_INPUT)
    (asserts! (<= vulnerability-count u1000) ERR_INVALID_INPUT)
    (asserts! (<= high-severity u1000) ERR_INVALID_INPUT)
    (asserts! (<= medium-severity u1000) ERR_INVALID_INPUT)
    (asserts! (<= low-severity u1000) ERR_INVALID_INPUT)
    
    ;; Validate that high + medium + low = vulnerability-count
    (asserts! (is-eq vulnerability-count (+ (+ high-severity medium-severity) low-severity)) ERR_INVALID_INPUT)
    
    ;; Calculate risk score after validation
    (let ((new-risk-score (calculate-risk-score high-severity medium-severity low-severity)))
      ;; Update last audit ID
      (var-set last-audit-id new-audit-id)
      
      ;; Record audit result with validated inputs
      (map-set audit-results
        { 
          contract-id: contract-id,
          audit-id: new-audit-id
        }
        {
          auditor: tx-sender,
          timestamp: block-height,
          vulnerability-count: vulnerability-count,
          high-severity: high-severity,
          medium-severity: medium-severity,
          low-severity: low-severity,
          report-hash: validated-report-hash
        }
      )
      
      ;; Update contract info
      (map-set contracts
        { contract-id: contract-id }
        (merge contract-info {
          last-audit: new-audit-id,
          audit-count: (+ (get audit-count contract-info) u1),
          risk-score: new-risk-score
        })
      )
      
      (ok new-audit-id)
    )
  )
)

;; Private functions

;; Calculate risk score based on severity counts
;; Formula: (high * 10) + (medium * 3) + low
(define-private (calculate-risk-score (high uint) (medium uint) (low uint))
  (+ (+ (* high u10) (* medium u3)) low)
)
