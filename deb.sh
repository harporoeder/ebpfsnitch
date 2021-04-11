DIR=$(pwd)
mkdir ebpfsnitch_0.3-1

cd "$DIR/build"
cmake -D CMAKE_INSTALL_PREFIX="/usr/bin" ..
make
make DESTDIR="$DIR/ebpfsnitch_0.3-1/" install

cd "$DIR/ui"
python setup.py install --root="$DIR/ebpfsnitch_0.3-1/"

mkdir -p "$DIR/ebpfsnitch_0.3-1/usr/lib/systemd/system"
cp "$DIR/ebpfsnitchd.service" "$DIR/ebpfsnitch_0.3-1/usr/lib/systemd/system/"

mkdir -p "$DIR/ebpfsnitch_0.3-1/DEBIAN/control"
cp "$DIR/control" "$DIR/ebpfsnitch_0.3-1/DEBIAN/control"