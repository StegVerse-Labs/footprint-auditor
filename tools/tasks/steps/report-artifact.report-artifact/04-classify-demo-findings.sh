python -m src.classifier.finding_classifier \
  --rules config/severity_rules.yaml \
  --input tmp/demo_findings.json \
  --output reports/classifier_summary.json
