### `GET /health`

```json
{
  "status": "healthy",
  "models_loaded": 7,
  "real_models": 5,
  "placeholder_models": 2,
  "timestamp": "..."
}

[
  {
    "name": "sqli",
    "type": "sqli",
    "loaded": true,
    "is_placeholder": false,
    "last_updated": "...",
    "version": 1,
    "metrics": null
  },
  {
    "name": "domain",
    "type": "domain",
    "loaded": true,
    "is_placeholder": true,
    "last_updated": "...",
    "version": 1,
    "metrics": null
  }
]