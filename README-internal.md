This README is for the internal information that should not be exported to the reviewers.

To export for CCS submission

1. Be sure to be on a clean commit.
2. Check mention of `shaih`:
   ```bash
   git ls-files | xargs grep -H shaih 
    ```
3. Change all `shaih` by `shaih`
   ```bash
   git ls-files | xargs -n1 sed -i 's/shaih/shaih/g'
   ```
   (requires gnu-sed on macOS)
4. Export:
   ```bash
   stashName=`git stash create`;
   git archive --format=zip --output=code.zip $stashName
   ```
5. Undo all changes:
   ```bash
   git stash drop
   ```

Mark the files as non-exportable using `.gitattributes`.

### On rsync-callisto*

These scripts are used to sync the folder with a VM names callisto/callisto2.
Useful for benchmarking.

### On forking libsodium

Contrary to other source codes using modified libsodium (such as the Algorand source code),
we do not have the same requirement of traceability, so we install `libsodium` independently:
https://github.com/algorand/go-algorand/issues/20#issuecomment-506777532
rather than forking libsodium repo / using a git submodule.