// DumpC.java —— Ghidra 无头脚本：给一串地址，把反编译伪代码直接写成文件
// 用法: -postScript DumpC.java <输出文件> <va> [<va> ...]
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DumpC extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("// 用法: DumpC.java <out.txt> <va> [<va> ...]");
            return;
        }
        String outPath = args[0];
        PrintWriter pw = new PrintWriter(outPath, "UTF-8");

        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        if (!di.openProgram(currentProgram)) {
            pw.println("// 打开程序失败");
            pw.close();
            return;
        }

        for (int i = 1; i < args.length; i++) {
            String s = args[i];
            String hex = s.toLowerCase().replace("0x", "").trim();
            long va;
            try {
                va = Long.parseLong(hex, 16);
            } catch (Exception e) {
                pw.println("// 无法解析地址: " + s);
                continue;
            }
            Address addr = toAddr(va);
            Function f = getFunctionAt(addr);
            if (f == null) {
                f = getFunctionContaining(addr);
            }
            if (f == null) {
                try {
                    disassemble(addr);
                    f = createFunction(addr, null);
                } catch (Exception e) {
                    pw.println("// " + s + " 创建函数失败: " + e.getMessage());
                }
                if (f == null) {
                    pw.println("// " + s + " 处没有函数");
                    continue;
                }
            }
            pw.println("\n// ==================== " + f.getName() + " @ " + f.getEntryPoint() + " ====================");
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            if (res != null && res.decompileCompleted()) {
                pw.println(res.getDecompiledFunction().getC());
            } else {
                pw.println("// 反编译失败: " + (res == null ? "null" : res.getErrorMessage()));
            }
            pw.flush();
        }
        di.dispose();
        pw.close();
        println("// 写出: " + outPath);
    }
}
