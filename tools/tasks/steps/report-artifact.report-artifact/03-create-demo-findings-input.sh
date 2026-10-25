mkdir -p tmp reports receipts
cat > tmp/demo_findings.json <<'JSON'
{
  "findings": [
    {
      "repo": "StegVerse-Labs/footprint-auditor",
      "message": "routine service metadata audit",
      "author_email": "builder@stegverse.org",
      "author_name": "StegVerse Bot"
    },
    {
      "repo": "StegVerse-Labs/footprint-auditor",
      "message": "remove medical note from public metadata",
      "author_email": "builder@stegverse.org",
      "author_name": "StegVerse Bot"
    },
    {
      "repo": "StegVerse-Labs/footprint-auditor",
      "message": "ordinary commit from personal account",
      "author_email": "person@example.com",
      "author_name": "Person"
    }
  ]
}
JSON
