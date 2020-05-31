package tm4;

import java.io.IOException;
import java.util.HashMap;

import ghidra.app.util.bin.BinaryReader;

public final class MainFuncsSegment {
	private final HashMap<String, Long> funcs = new HashMap<>();
	
	public MainFuncsSegment(BinaryReader reader, long startOffset) throws IOException {
		reader.setPointerIndex(startOffset);
		long count = reader.readNextUnsignedInt();
		
		for (int i = 0; i < count; ++i) {
			long nameOffset = reader.readNextUnsignedInt();
			long funcOffset = reader.readNextUnsignedInt();
			
			String name = reader.readAsciiString(startOffset + nameOffset);
			
			funcs.put(name, funcOffset);
		}
	}
	
	public final HashMap<String, Long> getSymbols() {
		return funcs;
	}
}
