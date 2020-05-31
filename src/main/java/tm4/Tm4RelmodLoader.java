/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package tm4;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.TimeUnit;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import generic.stl.Pair;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.reloc.InstructionStasher;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loads Twisted Metal 4 (PSX) RELMOD (.mod) modules
 */
public class Tm4RelmodLoader extends AbstractLibrarySupportLoader {

	public static final int TAG = 0x0014;
	private static final String OS_FUNCS_JSON = "os_funcs.json";
	
	private static final String MODULE_NAME = "TM4 Relative Module (.mod) Loader";
	
	@Override
	public String getName() {
		return MODULE_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		int tag = reader.readNextUnsignedShort();
		
		if (tag == TAG) {
			loadSpecs.add(new LoadSpec(this, 0x80000000, new LanguageCompilerSpecPair("MIPS:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		BinaryReader reader = new BinaryReader(provider, true);
		
		long codeOffset = reader.readNextUnsignedInt();
		long relocsOffset = reader.readNextUnsignedInt();
		long mainFuncsOffset = reader.readNextUnsignedInt();
		long importsOffset = reader.readNextUnsignedInt();
		long blockNameOffset = reader.readNextUnsignedInt();
		
		String name = findName(reader, blockNameOffset, log);
		
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);
		
		byte[] code = reader.readNextByteArray((int) (relocsOffset - codeOffset));
		
		MemoryBlock text = createSegment(fpa, name, 0x80000000, code, log);
		
		if (text == null) {
			return;
		}
		
		final RelocsSegment relocs = new RelocsSegment(reader, relocsOffset);
		final MainFuncsSegment mainFuncs = new MainFuncsSegment(reader, mainFuncsOffset);
		final ImportsSegment imports = new ImportsSegment(reader, importsOffset);
		
		SymbolTable st = program.getSymbolTable();
		
		try {
			TimeUnit.SECONDS.sleep(1);
		} catch (InterruptedException unused) {
			
		}
		
		File osFuncsFile;	
		
		try {
			osFuncsFile = Application.getModuleDataFile(OS_FUNCS_JSON).getFile(false);
		} catch (FileNotFoundException unused) {
			String osFuncsPath = showSelectFile("Select file...");
			Files.copy(Paths.get(osFuncsPath), Paths.get(Application.getModuleDataSubDirectory("").getAbsolutePath(), OS_FUNCS_JSON), StandardCopyOption.REPLACE_EXISTING);
			osFuncsFile = Application.getModuleDataFile(OS_FUNCS_JSON).getFile(false);
		}
		
		final HashMap<String, Long> osFuncs = parseOsFuncsFile(osFuncsFile.getAbsolutePath(), log);
		
		applyRelocs(fpa, relocs, text.getStart(), monitor, log);
		applyImports(program, imports, text.getStart(), osFuncs, log);
		
		applyMainFuncs(fpa, st, mainFuncs, text.getStart(), monitor, log);
		applyImportsRefs(fpa, st, imports, text.getStart(), osFuncs, monitor, log);
		
		disassemble(fpa, monitor, text.getStart());
	}
	
	private static String findName(BinaryReader reader, long startOffset, MessageLog log) {
		long offset = reader.getPointerIndex();
		reader.setPointerIndex(startOffset);
		
		String name = "";
		
		try {
			while ((reader.peekNextByte()) != 0x2A) {
					name += (char)reader.readNextByte();
			}
		} catch (IOException e) {
			log.appendException(e);
		}
		
		reader.setPointerIndex(offset);
		
		return name;
	}
	
	@SuppressWarnings("unchecked")
	private static final HashMap<String, Long> parseOsFuncsFile(String fileName, MessageLog log) {
		HashMap<String, Long> funcs = new HashMap<>();
		
		try {
			@SuppressWarnings("resource")
			String osFuncsJson = new Scanner(new File(fileName)).useDelimiter("\\Z").next();
			JSONObject jo = (JSONObject) new JSONParser().parse(osFuncsJson);
			
			for (String key : (Set<String>)jo.keySet()) {
				funcs.put(key, (Long)jo.get(key));
			}
		} catch (ParseException | FileNotFoundException e) {
			log.appendException(e);
		}
		
		return funcs;
	}
	
	private static String showSelectFile(String title) {
		JFileChooser jfc = new JFileChooser(new File("."));
		jfc.setDialogTitle(title);

		jfc.setFileFilter(new FileNameExtensionFilter(OS_FUNCS_JSON, "json"));
		jfc.setMultiSelectionEnabled(false);

		if (jfc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			return jfc.getSelectedFile().getAbsolutePath();
		}

		return null;
	}
	
	private static void applyRelocs(FlatProgramAPI fpa, final RelocsSegment relocs, Address base, TaskMonitor monitor, MessageLog log) {
		Program program = fpa.getCurrentProgram();
		Memory mem = program.getMemory();
		
		for (final Map.Entry<Long, Pair<Integer, Long>> entry : relocs.getRelocs().entrySet()) {
			int type = entry.getValue().first;
			
			Address from = base.add(entry.getKey() & 0xFFFFFFFC);
			
			InstructionStasher stasher = new InstructionStasher(program, from);
			
			try {
				int to = mem.getInt(from);
			
				switch (type) {
				case 0: {
					to += base.getOffset();
					mem.setBytes(from, intToBytes(to));
				} break;
				case 1: {
					to = (int) ((to & 0xFFFF0000) | ((entry.getValue().second + base.getOffset() + 0x8000) >> 0x10));
					mem.setBytes(from, intToBytes(to));
				} break;
				case 2: {
					int upper = to & 0xFFFF0000;
					int lower = (int) ((to + base.getOffset()) & 0xFFFF);
					mem.setBytes(from, intToBytes(upper | lower));
				} break;
				case 3: {
					int upper = to & 0xFC000000;
					int lower = (int) (((((to & 0x3FFFFFF) << 2) + base.getOffset()) >> 2) & 0x3FFFFFF);
					mem.setBytes(from, intToBytes(upper | lower));
				} break;
				}
				
				stasher.restore();
			} catch (CodeUnitInsertionException | MemoryAccessException e) {
				log.appendException(e);
				return;
			}
		}
	}
	
	private static void applyImports(Program program, final ImportsSegment imports, Address base, final HashMap<String, Long> osFuncs, MessageLog log) {
		Memory mem = program.getMemory();
		
		try {
			for (final Map.Entry<Long, Pair<Integer, Pair<String, Long>>> entry : imports.getImports().entrySet()) {
				long funcAddr = osFuncs.get(entry.getValue().second.first);
				
				int type = entry.getValue().first;
				
				Address from = base.add(entry.getKey() & 0xFFFFFFFC);
				
				InstructionStasher stasher = new InstructionStasher(program, from);
				
				try {
					int to = mem.getInt(from);
				
					switch (type) {
					case 0: {
						to += funcAddr;
						mem.setBytes(from, intToBytes(to));
					} break;
					case 1: {
						to = (int) ((to & 0xFFFF0000) | ((entry.getValue().second.second + funcAddr + 0x8000) >> 0x10));
						mem.setBytes(from, intToBytes(to));
					} break;
					case 2: {
						int upper = to & 0xFFFF0000;
						int lower = (int) ((to + funcAddr) & 0xFFFF);
						mem.setBytes(from, intToBytes(upper | lower));
					} break;
					case 3: {
						int upper = to & 0xFC000000;
						int lower = (int) (((((to & 0x3FFFFFF) << 2) + funcAddr) >> 2) & 0x3FFFFFF);
						mem.setBytes(from, intToBytes(upper | lower));
					} break;
					}
					
					stasher.restore();
				} catch (CodeUnitInsertionException | MemoryAccessException e) {
					log.appendException(e);
					return;
				}
			}
			
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
	}
	
	private static void applyImportsRefs(FlatProgramAPI fpa, SymbolTable st, final ImportsSegment imports, Address base, final HashMap<String, Long> osFuncs, TaskMonitor monitor, MessageLog log) {
		try {
			for (final Map.Entry<Long, Pair<Integer, Pair<String, Long>>> entry : imports.getImports().entrySet()) {
				long funcAddr = osFuncs.get(entry.getValue().second.first);
				
				Address funcAddr_ = fpa.toAddr(funcAddr);
				if (fpa.getMemoryBlock(funcAddr_) == null) {
					createSegment(fpa, String.format("IMP_%s", entry.getValue().second.first), funcAddr, new byte[] {0x00, 0x00, 0x00, 0x00}, log);
					fpa.createFunction(funcAddr_, entry.getValue().second.first);
				}
			}
			
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
	}
	
	private static void applyMainFuncs(FlatProgramAPI fpa, SymbolTable st, final MainFuncsSegment funcs, Address base, TaskMonitor monitor, MessageLog log) {
		for (final Map.Entry<String, Long> entry : funcs.getSymbols().entrySet()) {
			Address addr = base.add(entry.getValue() & 0xFFFFFFFC);
			fpa.addEntryPoint(addr);
			fpa.createFunction(addr, entry.getKey());
		}
	}
	
	private static byte[] intToBytes(int x) {
		ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(x);
		return buffer.array();
	}
	
	private static Instruction disassemble(FlatProgramAPI fpa, TaskMonitor monitor, Address start) {
		Program program = fpa.getCurrentProgram();
		Listing listing = program.getListing();
		Instruction instr = listing.getInstructionAt(start);
		
		if (instr == null) {
			DisassembleCommand dis = new DisassembleCommand(start, null, true);
			dis.applyTo(program, monitor);
			return listing.getInstructionAt(start);
		}
		
		return instr;
	}

	private static MemoryBlock createSegment(FlatProgramAPI fpa, final String name, long offset, byte[] data, MessageLog log) {
		try {
			MemoryBlock block = fpa.createMemoryBlock(name, fpa.toAddr(offset), data, false);
			block.setExecute(true);
			block.setRead(true);
			block.setWrite(true);
			block.setVolatile(false);
			
			return block;
		} catch (Exception e) {
			log.appendException(e);
			return null;
		}
	}
}
