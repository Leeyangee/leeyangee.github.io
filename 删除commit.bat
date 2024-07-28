git checkout --orphan nb
git add -A
git commit -m "first commit"
git branch -D main
git branch -m main
git push -f origin main