//Export analysis results as JSON for LCRE
//@category LCRE
//@author LCRE

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.*;

public class ExportAnalysis extends GhidraScript {

    private PrintWriter writer;
    private boolean firstItem;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportAnalysis.java <output_file>");
            return;
        }

        String outputPath = args[0];
        writer = new PrintWriter(new FileWriter(outputPath));

        try {
            writeJson();
        } finally {
            writer.close();
        }

        println("Analysis exported to: " + outputPath);
    }

    private void writeJson() throws Exception {
        writer.println("{");

        // Program info
        writeProgramInfo();
        writer.println(",");

        // Sections
        writeSections();
        writer.println(",");

        // Functions
        writeFunctions();
        writer.println(",");

        // Imports
        writeImports();
        writer.println(",");

        // Exports
        writeExports();
        writer.println(",");

        // Strings
        writeStrings();
        writer.println(",");

        // Entry points
        writeEntryPoints();
        writer.println(",");

        // Call graph
        writeCallGraph();

        writer.println("}");
    }

    private void writeProgramInfo() {
        writer.println("  \"program\": {");
        writer.println("    \"name\": " + jsonString(currentProgram.getName()) + ",");
        writer.println("    \"language\": " + jsonString(currentProgram.getLanguageID().toString()) + ",");
        writer.println("    \"compiler\": " + jsonString(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + ",");
        writer.println("    \"image_base\": " + currentProgram.getImageBase().getOffset() + ",");
        writer.println("    \"min_address\": " + currentProgram.getMinAddress().getOffset() + ",");
        writer.println("    \"max_address\": " + currentProgram.getMaxAddress().getOffset() + ",");
        writer.println("    \"endian\": " + jsonString(currentProgram.getLanguage().isBigEndian() ? "big" : "little") + ",");
        writer.println("    \"pointer_size\": " + currentProgram.getDefaultPointerSize());
        writer.println("  }");
    }

    private void writeSections() {
        writer.println("  \"sections\": [");
        firstItem = true;

        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            if (!firstItem) writer.println(",");
            firstItem = false;

            String perms = "";
            if (block.isRead()) perms += "r";
            else perms += "-";
            if (block.isWrite()) perms += "w";
            else perms += "-";
            if (block.isExecute()) perms += "x";
            else perms += "-";

            writer.println("    {");
            writer.println("      \"name\": " + jsonString(block.getName()) + ",");
            writer.println("      \"start\": " + block.getStart().getOffset() + ",");
            writer.println("      \"end\": " + block.getEnd().getOffset() + ",");
            writer.println("      \"size\": " + block.getSize() + ",");
            writer.println("      \"permissions\": " + jsonString(perms));
            writer.print("    }");
        }

        writer.println();
        writer.println("  ]");
    }

    private void writeFunctions() throws Exception {
        writer.println("  \"functions\": [");
        firstItem = true;

        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        int maxFunctions = 10000; // Limit to prevent huge outputs

        while (funcIter.hasNext() && count < maxFunctions) {
            Function func = funcIter.next();

            if (!firstItem) writer.println(",");
            firstItem = false;

            // Get callers
            Set<Address> callerAddrs = new HashSet<>();
            for (Reference ref : getReferencesTo(func.getEntryPoint())) {
                if (ref.getReferenceType().isCall()) {
                    callerAddrs.add(ref.getFromAddress());
                }
            }

            // Get callees
            Set<Address> calleeAddrs = new HashSet<>();
            for (Function calledFunc : func.getCalledFunctions(monitor)) {
                calleeAddrs.add(calledFunc.getEntryPoint());
            }

            writer.println("    {");
            writer.println("      \"name\": " + jsonString(func.getName()) + ",");
            writer.println("      \"address\": " + func.getEntryPoint().getOffset() + ",");
            writer.println("      \"size\": " + func.getBody().getNumAddresses() + ",");
            writer.println("      \"signature\": " + jsonString(func.getSignature().getPrototypeString()) + ",");
            writer.println("      \"callers\": " + addressSetToJson(callerAddrs) + ",");
            writer.println("      \"callees\": " + addressSetToJson(calleeAddrs) + ",");
            writer.println("      \"is_external\": " + func.isExternal() + ",");
            writer.println("      \"is_thunk\": " + func.isThunk());
            writer.print("    }");

            count++;
        }

        writer.println();
        writer.println("  ]");
    }

    private void writeImports() {
        writer.println("  \"imports\": [");
        firstItem = true;

        SymbolTable symTable = currentProgram.getSymbolTable();
        ExternalManager extMgr = currentProgram.getExternalManager();

        for (String libName : extMgr.getExternalLibraryNames()) {
            for (Symbol sym : symTable.getExternalSymbols()) {
                ExternalLocation extLoc = extMgr.getExternalLocation(sym);
                if (extLoc != null && libName.equals(extLoc.getLibraryName())) {
                    if (!firstItem) writer.println(",");
                    firstItem = false;

                    writer.println("    {");
                    writer.println("      \"library\": " + jsonString(libName) + ",");
                    writer.println("      \"name\": " + jsonString(sym.getName()) + ",");
                    writer.println("      \"address\": " + (sym.getAddress() != null ? sym.getAddress().getOffset() : 0) + ",");
                    writer.println("      \"ordinal\": 0");
                    writer.print("    }");
                }
            }
        }

        writer.println();
        writer.println("  ]");
    }

    private void writeExports() {
        writer.println("  \"exports\": [");
        firstItem = true;

        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getAllSymbols(true);

        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.isExternalEntryPoint() ||
                (sym.getSymbolType() == SymbolType.FUNCTION && sym.isGlobal())) {
                if (!firstItem) writer.println(",");
                firstItem = false;

                writer.println("    {");
                writer.println("      \"name\": " + jsonString(sym.getName()) + ",");
                writer.println("      \"address\": " + sym.getAddress().getOffset() + ",");
                writer.println("      \"ordinal\": 0");
                writer.print("    }");
            }
        }

        writer.println();
        writer.println("  ]");
    }

    private void writeStrings() {
        writer.println("  \"strings\": [");
        firstItem = true;

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        int count = 0;
        int maxStrings = 50000;

        while (dataIter.hasNext() && count < maxStrings) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String value = data.getValue().toString();
                if (value.length() >= 4) {
                    if (!firstItem) writer.println(",");
                    firstItem = false;

                    // Get cross-references to this string
                    List<Long> xrefs = new ArrayList<>();
                    for (Reference ref : getReferencesTo(data.getAddress())) {
                        xrefs.add(ref.getFromAddress().getOffset());
                    }

                    writer.println("    {");
                    writer.println("      \"value\": " + jsonString(value) + ",");
                    writer.println("      \"address\": " + data.getAddress().getOffset() + ",");
                    writer.println("      \"length\": " + value.length() + ",");
                    writer.println("      \"xrefs\": " + longListToJson(xrefs));
                    writer.print("    }");

                    count++;
                }
            }
        }

        writer.println();
        writer.println("  ]");
    }

    private void writeEntryPoints() {
        writer.println("  \"entry_points\": [");
        firstItem = true;

        SymbolTable symTable = currentProgram.getSymbolTable();
        AddressIterator entryPoints = symTable.getExternalEntryPointIterator();

        while (entryPoints.hasNext()) {
            Address addr = entryPoints.next();
            Symbol sym = symTable.getPrimarySymbol(addr);

            if (!firstItem) writer.println(",");
            firstItem = false;

            writer.println("    {");
            writer.println("      \"name\": " + jsonString(sym != null ? sym.getName() : "entry") + ",");
            writer.println("      \"address\": " + addr.getOffset() + ",");
            writer.println("      \"type\": \"entry\"");
            writer.print("    }");
        }

        writer.println();
        writer.println("  ]");
    }

    private void writeCallGraph() throws Exception {
        writer.println("  \"call_graph\": {");

        // Nodes
        writer.println("    \"nodes\": [");
        firstItem = true;
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            if (!firstItem) writer.println(",");
            firstItem = false;

            writer.println("      {");
            writer.println("        \"address\": " + func.getEntryPoint().getOffset() + ",");
            writer.println("        \"name\": " + jsonString(func.getName()));
            writer.print("      }");
        }
        writer.println();
        writer.println("    ],");

        // Edges
        writer.println("    \"edges\": [");
        firstItem = true;
        funcIter = currentProgram.getFunctionManager().getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            for (Function calledFunc : func.getCalledFunctions(monitor)) {
                if (!firstItem) writer.println(",");
                firstItem = false;

                writer.println("      {");
                writer.println("        \"from\": " + func.getEntryPoint().getOffset() + ",");
                writer.println("        \"to\": " + calledFunc.getEntryPoint().getOffset());
                writer.print("      }");
            }
        }
        writer.println();
        writer.println("    ]");

        writer.println("  }");
    }

    private String jsonString(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private String addressSetToJson(Set<Address> addrs) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Address addr : addrs) {
            if (!first) sb.append(", ");
            first = false;
            sb.append(addr.getOffset());
        }
        sb.append("]");
        return sb.toString();
    }

    private String longListToJson(List<Long> longs) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Long l : longs) {
            if (!first) sb.append(", ");
            first = false;
            sb.append(l);
        }
        sb.append("]");
        return sb.toString();
    }
}
