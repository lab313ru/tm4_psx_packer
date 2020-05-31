package tm4;

import java.io.IOException;
import java.util.HashMap;

import generic.stl.Pair;
import ghidra.app.util.bin.BinaryReader;

public final class ImportsSegment {
	private HashMap<Long, Pair<Integer, Pair<String, Long>>> symbols = new HashMap<>();
	
	public ImportsSegment(BinaryReader reader, long startOffset) throws IOException {
		reader.setPointerIndex(startOffset);
		long totalCount = reader.readNextUnsignedInt();
		
		for (int i = 0; i < totalCount; ++i) {
			String name = reader.readNextAsciiString();
			
			long offset = reader.getPointerIndex();
			long delta = offset % 4;
			if (delta != 0) {
				reader.setPointerIndex(offset + (4 - delta));
			}

			long refsCount = reader.readNextUnsignedInt();
			
			for (int j = 0; j < refsCount; ++j) {
				long ref = reader.readNextUnsignedInt();
				long from = ref & 0xFFFFFFFCL;
				int type = (int) (ref & 3);
				
				switch (type) {
				case 1: {
					symbols.put(from, new Pair<>(type, new Pair<>(name, reader.readNextUnsignedInt())));
				} break;
				default: {
					symbols.put(from, new Pair<>(type, new Pair<>(name, 0L)));
				}
				}
			}
		}
	}
	
	public final HashMap<Long, Pair<Integer, Pair<String, Long>>> getImports() {
		return symbols;
	}
}
