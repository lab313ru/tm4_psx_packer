package tm4;

import java.io.IOException;
import java.util.HashMap;

import generic.stl.Pair;
import ghidra.app.util.bin.BinaryReader;

public final class RelocsSegment {
	private final HashMap<Long, Pair<Integer, Long>> relocs = new HashMap<>();
	
	public RelocsSegment(BinaryReader reader, long startOffset) throws IOException {
		reader.setPointerIndex(startOffset);
		
		long reloc = reader.readNextUnsignedInt();
		
		while (reloc != 0xFFFFFFFFL) {
			int type = (int) (reloc & 3);
			long from = reloc & 0xFFFFFFFCL;
			
			switch (type) {
			case 1: {
				relocs.put(from, new Pair<>(type, reader.readNextUnsignedInt()));
			} break;
			default: {
				relocs.put(from, new Pair<>(type, 0L));
			}
			}
			
			reloc = reader.readNextUnsignedInt();
		}
	}
	
	public final HashMap<Long, Pair<Integer, Long>> getRelocs() {
		return relocs;
	}
}
