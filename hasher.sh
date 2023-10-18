while read -r line; do
  hash=$(echo -n "$line" | sha256sum | cut -d ' ' -f 1)
  echo "$line" > "output_folder/$hash"
done