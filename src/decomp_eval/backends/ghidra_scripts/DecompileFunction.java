// Decompile exactly one named function and write only its C output.
// @category DecompileEval

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompileFunction extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: DecompileFunction.java <output-file> <function-name> [timeout-seconds]"
            );
        }
        Path output = Paths.get(args[0]);
        String requestedName = args[1];
        int timeoutSeconds = args.length >= 3 ? Integer.parseInt(args[2]) : 120;

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
                output,
                result.getDecompiledFunction().getC().getBytes(StandardCharsets.UTF_8)
            );
        }
        finally {
            decompiler.dispose();
        }
    }
}
