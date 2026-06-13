#!/usr/bin/env bash
# Regenerate the Exclusive-C14N golden outputs from the committed *.in.xml inputs
# using the libxml2 reference (xmllint).
#
# CAVEAT: xmllint --exc-c14n emits the *with-comments* profile (its --help says
# so, and there is no CLI flag for the without-comments form). XML-DSig / XAdES —
# and therefore our `c14n::excl_c14n` — use the *without-comments* profile
# (method URI http://www.w3.org/2001/10/xml-exc-c14n#). The two profiles differ
# ONLY on comment nodes, so every comment-free vector's golden is valid for both;
# any vector whose input contains a comment is fixed up below.
set -euo pipefail
cd "$(dirname "$0")"

for f in *.in.xml; do
  xmllint --exc-c14n "$f" > "${f%.in.xml}.out.xml"
done

# without-comments fix-ups (inputs containing comment nodes):
printf '%s' '<r><c>keep</c></r>' > 05-comment-dropped.out.xml

echo "regenerated $(ls -1 ./*.in.xml | wc -l) vectors"
