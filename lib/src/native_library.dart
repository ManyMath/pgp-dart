import 'dart:ffi';
import 'dart:io';

DynamicLibrary _loadLibrary() {
  final libraryBaseNames = <String>[
    'pgp_flutter_native',
    'pgp_ffi',
  ];

  final libraryFileNames = switch (Platform.operatingSystem) {
    'macos' ||
    'ios' =>
      libraryBaseNames.map((name) => 'lib$name.dylib').toList(),
    'android' ||
    'linux' =>
      libraryBaseNames.map((name) => 'lib$name.so').toList(),
    'windows' => libraryBaseNames.map((name) => '$name.dll').toList(),
    _ => throw UnsupportedError(
        'Unsupported platform: ${Platform.operatingSystem}',
      ),
  };

  final executableDir = File(Platform.resolvedExecutable).parent;
  final attempted = <String>[];
  Object? lastError;
  for (final libraryFileName in libraryFileNames) {
    final candidates = <String>[
      libraryFileName,
      '${executableDir.path}/$libraryFileName',
      '${executableDir.path}/lib/$libraryFileName',
      '${Directory.current.path}/$libraryFileName',
      '${Directory.current.path}/lib/$libraryFileName',
      // The crate's own build output, so `dart run` works from the package
      // root straight after `cargo build --release`.
      '${Directory.current.path}/pgp-ffi/target/release/$libraryFileName',
    ];

    for (final candidate in candidates) {
      try {
        return DynamicLibrary.open(candidate);
      } catch (error) {
        attempted.add(candidate);
        lastError = error;
      }
    }
  }

  throw ArgumentError(
    'Failed to load native library. Tried: ${libraryFileNames.join(', ')}\n'
    'Resolved executable: ${Platform.resolvedExecutable}\n'
    'Current directory: ${Directory.current.path}\n'
    'Attempted paths:\n${attempted.map((path) => '- $path').join('\n')}\n'
    'Last error: $lastError',
  );
}

final DynamicLibrary nativeLibrary = _loadLibrary();
