// Decompile one mapped target function for each imported program.
// @category DecompileEval

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileBatch extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: DecompileBatch.java <output-dir> <mapping-tsv> [timeout-seconds]"
            );
        }
        Path outputDir = Paths.get(args[0]);
        Path mappingFile = Paths.get(args[1]);
        int timeoutSeconds = args.length >= 3 ? Integer.parseInt(args[2]) : 120;
        Map<String, String> targets = readMapping(mappingFile);
        String programName = currentProgram.getName();
        String requestedName = targets.get(programName);
        if (requestedName == null) {
            throw new IllegalStateException("no target mapping for program: " + programName);
        }

        Function target = null;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (requestedName.equals(function.getName()) ||
                requestedName.equals(function.getName(true))) {
                target = function;
                break;
            }
        }
        if (target == null) {
            throw new IllegalStateException("function not found: " + requestedName);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("cannot open program in Ghidra decompiler");
            }
            DecompileResults result = decompiler.decompileFunction(target, timeoutSeconds, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException(
                    "decompilation failed for " + requestedName + ": " + result.getErrorMessage()
                );
            }
            Files.write(
                outputDir.resolve(programName + ".c"),
                result.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8)
            );
        }
        finally {
            decompiler.dispose();
        }
    }

    private Map<String, String> readMapping(Path path) throws Exception {
        Map<String, String> result = new HashMap<>();
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        for (String line : lines) {
            int separator = line.indexOf('\t');
            if (separator > 0) {
                result.put(line.substring(0, separator), line.substring(separator + 1));
            }
        }
        return result;
    }
}
