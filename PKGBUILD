# Maintainer: Harpo Roeder <roederharpo@protonmail.ch>

pkgname="ebpfsnitch"
pkgver=0.1.0
pkgrel=1
pkgdesc="eBPF based Application Firewall"
arch=("x86_64")
license=('BSD3')

depends=(
    'cmake'
    'clang'
    'bpf'
    'libbpf'
    'libnetfilter_queue'
    'spdlog'
    'boost'
    'libmnl'
    'nlohmann-json'
    'python3'
    'python-pyqt5'
    'conntrack-tools'
)

source=('git+https://github.com/harporoeder/ebpfsnitch.git#branch=hr/pkgbuild')
sha256sums=('SKIP')

build() {
    cmake -DCMAKE_INSTALL_PREFIX="/usr/bin" -B build -S "${pkgname}"
    make -C build
}

package() {
    cd build
    make DESTDIR="$pkgdir/" install
    cd "$srcdir/ebpfsnitch/ui"
    python setup.py install --root="$pkgdir/"
    cd "$srcdir/ebpfsnitch"
    install -Dm644 ebpfsnitchd.service -t "$pkgdir/usr/lib/systemd/system"
}
