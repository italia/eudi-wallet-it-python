echo -e '\nHTML linting:'
shopt -s globstar nullglob
for file in `find example -type f  | grep html`
do
  echo -e "\n$file:"
  html_lint.py "$file" | awk -v path="file://$PWD/$file:" '$0=path$0' | sed -e 's/: /:\n\t/';
done

errors=0
for file in "${array[@]}"
do
  errors=$((errors + $(html_lint.py "$file" | grep -c 'Error')))
done

echo -e "\nHTML errors: $errors"
if [ "$errors" -gt 0 ]; then exit 1; fi;
