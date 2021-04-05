# Maintainer: Harpo Roeder <roederharpo@protonmail.ch>

pkgname='ebpfsnitch'
pkgver=0.2.0
pkgrel=2
pkgdesc='eBPF based Application Firewall'
arch=('x86_64')
license=('BSD3')

provides=('ebpfsnitch' 'ebpfsnitchd')

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

source=("https://github.com/harporoeder/ebpfsnitch/archive/refs/tags/$pkgver.tar.gz")
sha256sums=('0a5f082db00ff1a9fb14f7bd6392e7c9e034999b4fa7b8ec7500205b24a33d22')

build() {
    cd "$srcdir/ebpfsnitch-$pkgver"
    mkdir build && cd build
    cmake -D CMAKE_INSTALL_PREFIX="/usr/bin" ..
    make
}

package() {
    cd "$srcdir/ebpfsnitch-$pkgver/build"
    make DESTDIR="$pkgdir/" install
    cd "$srcdir/ebpfsnitch-$pkgver/ui"
    python setup.py install --root="$pkgdir/"
    cd "$srcdir/ebpfsnitch-$pkgver"
    install -Dm644 ebpfsnitchd.service -t "$pkgdir/usr/lib/systemd/system"
}
