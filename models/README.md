# Models

Pre-trained model files used by `vajra.ml` and the experimental engines.

None of these models has a documented training dataset, evaluation or data
licence yet, so treat every prediction they make as unvalidated. The
descriptions below come from inspecting the files without loading them.

## Loading safety

`.pkl` and `.joblib` files are Python pickles, and loading one can run
arbitrary code. Only load model files from this repository or another source
you trust, and check them against the SHA-256 sums below. Pull requests that
add or change model files need a maintainer review.

## Inventory

| File | What it is | Used by | Status |
| --- | --- | --- | --- |
| `eta_model.pkl` | Dict holding an imbalanced-learn pipeline (StandardScaler, SMOTE, RandomForest), a protocol encoder and a decision threshold. Classifies flows as `benign` or attack classes such as `attack_c2` and `attack_port_scan`. | `vajra.experimental.engines.eta` through `vajra.ml.loader` | Loads with scikit-learn 1.7, NumPy 2 and imbalanced-learn (`pip install -e ".[ml]"`). Not started by the default pipeline. |
| `deep_insider_threat_model.pkl` | PyTorch insider-threat network with a MinMaxScaler, over user-activity features such as logon counts, night logons, USB use and external email. | `vajra.ml.loader` | Does not load: it was pickled from a training script's `__main__`. The loader falls back to a placeholder that predicts benign. |
| `domain_classifier.h5` | Keras character-level CNN and BiLSTM over domain names, expecting 80 character indices. | `vajra.api.inference`, `vajra.ml.loader` | Loads, but the current code feeds it numeric features rather than encoded characters, so its output is not meaningful. |
| `gnn_fingerprint.tflite` | TensorFlow Lite graph model with two inputs, node features and an adjacency matrix. | `vajra.api.inference`, `vajra.ml.loader` | The current code supplies only the node features. |
| `backdoor_detection/` | SGDClassifier with label encoders and a scaler over packet fields such as MAC and IP addresses, TCP flags and packet length. | `vajra.api.inference` | The current code builds a different feature set from what the model was trained on. |
| `mitm.joblib` | A fitted StandardScaler only, with no classifier. | Nothing | Unused. |

## Checksums

```
c717144ad4685deb23276c00da8d462873a93ee706de84cabfdf86813a832a55  eta_model.pkl
6771f89c770811b10f371b94788532b05d383516de9a01d3dd78c1ad9cd6ffa8  deep_insider_threat_model.pkl
1c1f7521dd6626d11be9aa5cd254164e14d4241f8fb4041c1b1f0eee3446f34e  domain_classifier.h5
9435aa460bebfcabb0950ce67f460e48367e91dbedb8f90967c610da93205eaa  gnn_fingerprint.tflite
016d5dc3085e75d35962d2b34c817849c2870a6150c734409afef03c1e507afd  backdoor_detection/backdoor_model.pkl
768b03325b2299f0b4fbe4f831ec46d429194025ddf50903175ecc457f992174  backdoor_detection/label_encoders.pkl
99a87ab29c3d07f8eac4a3094d3ae244b782e7812b1fdfb3fb972d7cbb7a1f21  backdoor_detection/scaler.pkl
f35146eeaeed25d48ccbbc68ff4ab688caf1c2b0b317d8ee492df78019644665  mitm.joblib
```

Verify them from this directory with `shasum -a 256 -c` (or `sha256sum -c`).

## Adding a model

A new model needs, alongside the file:

- what it predicts and the exact input features it expects
- the dataset it was trained on, and that dataset's licence
- how it was evaluated, with numbers someone else can reproduce
- the library versions needed to load it
- its SHA-256 in the table above
