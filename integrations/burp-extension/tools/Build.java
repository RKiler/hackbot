import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

class Build {
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !Files.isRegularFile(Path.of(args[0]))) {
            throw new IllegalArgumentException("Provide a local Montoya API JAR path");
        }
        Path api = Path.of(args[0]).toAbsolutePath();
        Path build = Path.of("build").toAbsolutePath();
        Path classes = build.resolve("classes");
        Path testClasses = build.resolve("test-classes");
        Files.createDirectories(classes);
        Files.createDirectories(testClasses);
        compile(Path.of("src/main/java"), classes, api.toString());
        compile(Path.of("src/test/java"), testClasses, classes + ":" + api);

        Manifest manifest = new Manifest();
        Attributes attributes = manifest.getMainAttributes();
        attributes.putValue("Manifest-Version", "1.0");
        attributes.putValue("Main-Class", "org.bughunter.burp.HackbotBurpExtension");
        Path jar = build.resolve("hackbot-burp-bridge.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar), manifest);
             var files = Files.walk(classes)) {
            for (Path file : files.filter(Files::isRegularFile).sorted().toList()) {
                JarEntry entry = new JarEntry(classes.relativize(file).toString().replace('\\', '/'));
                output.putNextEntry(entry);
                Files.copy(file, output);
                output.closeEntry();
            }
        }
        System.out.println("Built " + jar);
    }

    private static void compile(Path source, Path output, String classpath) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("JDK compiler module is required");
        }
        List<Path> files;
        try (var stream = Files.walk(source)) {
            files = stream.filter(path -> path.toString().endsWith(".java")).sorted().toList();
        }
        if (files.isEmpty()) {
            throw new IllegalStateException("No extension sources found");
        }
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, null, null)) {
            var units = manager.getJavaFileObjectsFromPaths(files);
            var options = List.of("-source", "17", "-target", "17", "-encoding", "UTF-8", "-classpath", classpath,
                                  "-d", output.toString());
            if (!compiler.getTask(null, manager, null, options, null, units).call()) {
                throw new IllegalStateException("Extension compilation failed");
            }
        }
    }
}
