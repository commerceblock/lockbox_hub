# lockbox hub
Shared secret provisioning for multiple lockbox enclaves

## Docker build

### Build docker image by executing:
```bash
docker build -t commerceblock/lockbox_hub .
```

### Run image without SGX driver:
```bash
docker run --rm -it commerceblock/lockbox_hub bash
cd /root/lockbox_hub/app
```

### Run image with SGX driver:
```bash
docker run --rm -it --device /dev/isgx commerceblock/lockbox_hub bash
cd /root/lockbox_hub/app
```
# Issue Tracker

# License 

Mercury Wallet is released under the terms of the GNU General Public License. See for more information https://opensource.org/licenses/GPL-3.0
