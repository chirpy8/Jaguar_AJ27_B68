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
package jaguar_aj27_b68;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This loader loads binaries with b68 extension for Jaguar AJ27 ECM files using HC16 processor
 * It will also load binaries tagged as cpu files but with additional data on tpu and slim memory areas
 * AJ26 ECM files, which are also have b68 extension, are ignored as these have different file format with no header
 * The processors are known to be 68HC916Y6 variant, and interrupt vector labels/functions and SLIM labels are added
 * If the specific file name is matched, additional analysis actions will be taken
 */
public class Jaguar_AJ27_B68Loader extends AbstractLibrarySupportLoader {
	
	
	public enum AJ27fileType {MAINCAL, SUBCAL, MAINBOOT, SUBBOOT, UNKNOWN}
	AJ27fileType fileType = AJ27fileType.UNKNOWN;

	@Override
	public String getName() {


		return "b68 Jaguar AJ27";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// check if filename extension is b68
		// check if first 2 bytes (0 and 1) are 0x04 0x00
		// check if bytes 4 and 5 are one of the following 0x signatures
		//		aa 00, f0 97, 03 15
		//		corresponding to cal file, main boot file, or sub boot file
		// check if length parameter in file header is 4, 5 or 160 (or 168 for custom cpu files)
		// check if total bytes in file is 6 + 1029*lengthParameter, i.e. cross check length parameter
		// check if last 2 bytes in file are 00 00 (not for 168 length files)
		// if these checks pass, create HC16 loadSpec
		
		
		final long START_OFFSET = 0;
		final long START_LEN = 2;
		final long SIG_OFFSET = 4;
		final long SIG_LEN = 2;
		
		byte[] START_SEQ = {(byte) 0x04,(byte) 0x00};
		byte[] CAL_SEQ = {(byte) 0x54,(byte) 0xaa};
		byte[] MAIN_BOOT_SEQ = {(byte) 0xf0,(byte) 0x97};
		byte[] SUB_BOOT_SEQ = {(byte) 0x03,(byte) 0x15};
		
		boolean validName =  provider.getName().endsWith(".B68") || provider.getName().endsWith(".b68");
		
		byte[] startSeq = provider.readBytes(START_OFFSET, START_LEN);
		boolean validStart = Arrays.equals(startSeq, START_SEQ);
		
		byte[] sigSeq = provider.readBytes(SIG_OFFSET, SIG_LEN);
		
		boolean calFile = Arrays.equals(sigSeq, CAL_SEQ);
		boolean mainBoot = Arrays.equals(sigSeq, MAIN_BOOT_SEQ);
		boolean subBoot = Arrays.equals(sigSeq, SUB_BOOT_SEQ);
		
		boolean validSignature = calFile || mainBoot || subBoot;
				
		final long LENGTH_OFFSET = 3;
		int totalBlocks = Byte.toUnsignedInt(provider.readByte(LENGTH_OFFSET));
		
		boolean validLengthParam =
				(totalBlocks == 4) || (totalBlocks == 5) || (totalBlocks == 160) || (totalBlocks == 168);
		
		long fileLength = provider.length();
		boolean validFileLength = (fileLength == ((totalBlocks*1029) + 6));
		
		final long END_OFFSET = -2;
		final long END_LEN = 2;
		byte[] END_SEQ = {(byte) 0x00,(byte) 0x00};
		byte[] endSeq = provider.readBytes(fileLength+END_OFFSET, END_LEN);
		
		boolean validEnd = Arrays.equals(endSeq, END_SEQ);
		
		if (validName && validStart && validSignature
				&& validLengthParam && validFileLength && validEnd)
		{
			loadSpecs.add(new LoadSpec(this, 0, 
				new LanguageCompilerSpecPair("HC16:BE:32:default","default"),true));
		}

		return loadSpecs;
	}
	
	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}
	

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// Get expected number of blocks in header
		// Load bytes into array of 168 * 1k blocks, since we know there can't be more than 168k for AJ27 HC16Y6 processor
		// Check number of blocks matches expected number
		// Determine number of contiguous blocks and start and end point of each
		// Create memory for each contiguous block and load data
		
		// Check name for match to do post load analysis
		// if match, perform analysis including execute scripts, add entry point, etc.
		//
		
		final long LENGTH_OFFSET = 3;
		int totalBlocks = Byte.toUnsignedInt(provider.readByte(LENGTH_OFFSET));
		
		// array of byte array to store file bytes in 1k blocks
		byte[][] fileData = new byte[168][1024];
		//array to capture block pointer values
		long[] blockPointers = new long[168];
		
		try
		{
			//read all available blocks and store	
			for (int x=0; x < totalBlocks; x++)
			{
				//read a 1k block and store in fileData
				fileData[x] = provider.readBytes(9+(x*1029),1024);
				// initialize variable for block pointer (base address where block will be loaded)
				long blockPointer = 0;
				// get 3 byte block pointer from file and compute big endian value
				byte[] pointerBytes = provider.readBytes(6+(x*1029),3);
				int shiftLeft = 16;
				for (byte b : pointerBytes)
				{
					blockPointer = blockPointer + (Byte.toUnsignedInt(b) << shiftLeft);
					shiftLeft -= 8;
				}
				blockPointers[x] = blockPointer;
			}
			
			//determine contiguous blocks, start addresses, and lengths
			
			//create class to store contiguous block
			class blockSpec
			{
				private int index; //position where data set starts in loaded data stored in fileData , from 1 - 168
				private long startAddr; //starting address of this block
				private int len; //length of this block in 1k chunks, from 1 - 168
				private byte[] contents; //data for this block
				
				public blockSpec(long startAddrVal, int lenVal, int startIndex, byte[][] dataSet)
				{
					startAddr = startAddrVal;
					len = lenVal;
					index = startIndex;
					contents = new byte[len*1024];
					for (int x=0;x<len;x++)
					{
						System.arraycopy(dataSet[x+index],0,contents,x*1024,1024);
					}
				}
				
				public long getStartAddr()
				{
					return startAddr;
				}
				
				public int getLen()
				{
					return len;
				}
				
				public byte[] getContents()
				{
					byte[] dataCopy = Arrays.copyOf(contents, contents.length);
					return dataCopy;
				}
				
			}
			
			//iterate through all 1k blocks, create a blockSpec for each contiguous block
			
			//list to hold the contiguous block specs
			ArrayList<blockSpec> contigBlocks = new ArrayList<blockSpec>();
			
			long startBlockPointer = blockPointers[0];
			int currentLength = 0;
			int startIndex = 0;
			if (totalBlocks > 1) //need to treat single 1k block as special case with else...
			{
				for (int x=0; x < (totalBlocks-1); x++)
				{
					//note - will fail if only a single 1k block exists....not relevant for target files
					
					// note will not work for flawed file format created by BDM downloads
					// this determines contiguous blocks based on difference between block pointers of 1
					// which is incorrect, it should be a difference of 1024 as per below
					
					if ((blockPointers[x+1] - blockPointers[x]) != 1024)
					{
						contigBlocks.add(new blockSpec(startBlockPointer, currentLength+1, startIndex, fileData));
						currentLength=0;
						startBlockPointer = blockPointers[x+1];
						startIndex = x+1;
					}
					else
					{
						currentLength++;
					}
				}
			}
			else
			{
				currentLength = 1;
			}
			
			contigBlocks.add(new blockSpec(startBlockPointer, currentLength+1, startIndex, fileData));
	
			//create memory blocks based on contigBlocks
			
			FlatProgramAPI flatAPI = new FlatProgramAPI(program);
			int blockIndex = 0;

			for (blockSpec bspec : contigBlocks) {
				String msg = "Creating memory block at 0x"+Long.toHexString(bspec.getStartAddr())+
						" with length 0x"+Integer.toHexString(bspec.getLen()*1024);
				monitor.setMessage(msg);
				String bIndex = Integer.toString(blockIndex);
				Address startAddr = flatAPI.toAddr(bspec.getStartAddr());
				MemoryBlock block = flatAPI.createMemoryBlock("Block"+bIndex, startAddr, bspec.getContents(), false);
				block.setPermissions(true,  false,  true); //read and execute, not write
				blockIndex++;
			}
			
			// using reset vectors at bytes 0 - 7, setup up entry point from initial PC value
			// but only if these bytes have been loaded (note no reset vectors loaded for boot images)
			Address resetVectorsAddr = flatAPI.toAddr(0);
			MemoryBlock mb = flatAPI.getMemoryBlock(resetVectorsAddr);
			if (mb != null)
			{
				byte[] resetVectorInfo = flatAPI.getBytes(resetVectorsAddr, 8);
				
	//			int zkValue = Byte.toUnsignedInt( (byte) (resetVectorInfo[0] & 0x0f)); // bits 0-3
	//			int skValue = Byte.toUnsignedInt( (byte) ((resetVectorInfo[1] & 0xf0) >> 4)); // bits 4-7
				int pkValue = Byte.toUnsignedInt( (byte) (resetVectorInfo[1] & 0x0f)); // bits 0-3
				
				int pcValue = (Byte.toUnsignedInt(resetVectorInfo[2]) << 8) + Byte.toUnsignedInt(resetVectorInfo[3]);
	//			int spValue = (Byte.toUnsignedInt(resetVectorInfo[4]) << 8) + Byte.toUnsignedInt(resetVectorInfo[5]);
	//			int izValue = (Byte.toUnsignedInt(resetVectorInfo[6]) << 8) + Byte.toUnsignedInt(resetVectorInfo[7]);
				
				BigInteger pce = BigInteger.valueOf((pkValue << 16) + pcValue);
	//			BigInteger spe = BigInteger.valueOf((skValue << 16) + spValue);
	//			BigInteger ize = BigInteger.valueOf((zkValue << 16) + izValue);
				
				flatAPI.addEntryPoint(flatAPI.toAddr(pce.longValue()));
				
				//mark the interrupt service routine vector pointers and functions
				HC16InterruptVectorsISRs(flatAPI);
			}
			
			//Apply the labels and data types for the HC16Y5 SLIM area
			HC16Y5Labels(flatAPI);
			
			//apply file specific labels if file is for MainCal-IC501 or SubCal-IC601
			//and labels option is not unchecked
			char keyChar = provider.getName().charAt(4);
			if (keyChar == 'C' || keyChar == 'c')
				fileType = AJ27fileType.MAINCAL;
			if (keyChar == 'D' || keyChar == 'd')
				fileType = AJ27fileType.SUBCAL;
			if (keyChar == 'A' || keyChar == 'a')
				fileType = AJ27fileType.MAINBOOT;
			if (keyChar == 'B' || keyChar == 'b')
				fileType = AJ27fileType.SUBBOOT;
			
			boolean addFileSpecificLabels = ((Boolean) options.get(0).getValue()).booleanValue();

			if (((fileType == AJ27fileType.MAINCAL) || (fileType == AJ27fileType.MAINBOOT)) && addFileSpecificLabels )
			{
				//file is a IC501 file
				mainCalLabels(flatAPI);
				AN82527Labels(flatAPI);
				if (fileType == AJ27fileType.MAINCAL)
				{
					calLabels(flatAPI);
					Address commentAddress = flatAPI.toAddr(0xb1020);
					flatAPI.setPlateComment(commentAddress, "RAM section from 0xb1020 to 0xb125f used to send\n data to sister processor IC601 via RAM buffered SPI");
					commentAddress = flatAPI.toAddr(0xb1260);
					flatAPI.setPlateComment(commentAddress, "RAM section from 0xb1260 to 0xb149f used to receive\n data from sister processor IC601 via RAM buffered SPI");
				}
			}
			
			if (((fileType == AJ27fileType.SUBCAL) || (fileType == AJ27fileType.SUBBOOT)) && addFileSpecificLabels )
			{
				//file is a IC601 file
				if (fileType == AJ27fileType.SUBCAL)
				{
					calLabels(flatAPI);
					Address commentAddress = flatAPI.toAddr(0xb1020);
					flatAPI.setPlateComment(commentAddress, "RAM section from 0xb1020 to 0xb125f used to send\n data to sister processor IC501 via RAM buffered SPI");
					commentAddress = flatAPI.toAddr(0xb1260);
					flatAPI.setPlateComment(commentAddress, "RAM section from 0xb1260 to 0xb149f used to receive\n data from sister processor IC501 via RAM buffered SPI");
				}
			}
			
			//loading finished
			monitor.setMessage("Completed loading");
		}
		catch (Exception e)
		{
			e.printStackTrace();
			throw new IOException("Failed to load b68 file");
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		
		// single Boolean option is added
		// a checkbox will be rendered using the default BooleanEditorComponent in OptionsEditorPanel
		List<Option> list = new ArrayList<Option>();
		Option fsl = new Option("Apply File Specific Labels and Memory Blocks", Boolean.TRUE);
		list.add(fsl);
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// both true and false values of the Option are valid, so no need to check
		// note in general, need to check each option, and if not acceptable return a String describing the issue
		// returning null indicates all options are valid

		return null;
	}
	
	private void HC16InterruptVectorsISRs(FlatProgramAPI fapi) throws Exception
	{
		// label interrupt vectors, and use vector to create function at interrupt service routine location
		String[][] vectorsData = {
				{"a", "BERR"},
				{"c", "SWI"},
				{"e", "Illegal_Inst"},
				{"10", "DivideZero"},
				{"12", "Unassigned,Reserved_1"},
				{"14", "Unassigned,Reserved_2"},
				{"16", "Unassigned,Reserved_3"},
				{"18", "Unassigned,Reserved_4"},
				{"1a", "Unassigned,Reserved_5"},
				{"1c", "Unassigned,Reserved_6"},
				{"1e", "Uninitialized_Interrupt"},
				{"20", "Unassigned,Reserved_7"},
				{"22", "Level_1_Interrupt_Autovector"},
				{"24", "Level_2_Interrupt_Autovector"},
				{"26", "Level_3_Interrupt_Autovector"},
				{"28", "Level_4_Interrupt_Autovector"},
				{"2a", "Level_5_Interrupt_Autovector"},
				{"2c", "Level_6_Interrupt_Autovector"},
				{"2e", "Level_7_Interrupt_Autovector"},
				{"30", "Spurious_Interrupt"},
				{"8", "BKPT"}
		};
		
		for (String[] s : vectorsData)
		{
			createVector(fapi, s[0], s[1]);
		}
			
		int labelCount = 8;
		for (int x=0x32; x < 0x70 ;x += 2)
		{
			Address address = fapi.toAddr(x);
			Data pointer16 = fapi.createData(address, Pointer16DataType.dataType);
			String intLabel = "Unassigned,Reserved_" + Integer.toString(labelCount);
			labelCount++;
			fapi.createLabel(address,intLabel+"_IV",false);
			address = (Address) pointer16.getValue();
			if (fapi.getFunctionAt(address) == null)		
				fapi.createFunction(address,intLabel+"_ISR");	
		}

		labelCount = 1;
		for (int x=0x70; x < 0x200 ;x += 2)
		{
			Address address = fapi.toAddr(x);
			Data pointer16 = fapi.createData(address, Pointer16DataType.dataType);
			String intLabel = "User_Defined_" + Integer.toString(labelCount);
			labelCount++;
			fapi.createLabel(address,intLabel+"_IV",false);
			address = (Address) pointer16.getValue();
			if (fapi.getFunctionAt(address) == null)		
				fapi.createFunction(address,intLabel+"_ISR");	
		}


	}
	
	private void HC16Y5Labels(FlatProgramAPI fapi) throws Exception
	{
		Address address = fapi.toAddr(0xFF000);
		byte Y6cpuType = (byte) (0xd0 & 0xff); // Y5 is 0xcc, Y6 os 0xd0
		boolean isY6 = false; // default to Y5 labels unless slim area is populated and shows Y6 type
		
		MemoryBlock mb = fapi.getMemoryBlock(address);
		if (mb == null)
		{
			mb = fapi.createMemoryBlock("SlimMemorySpace", address, null, 0x1000, false);
		}
		else
		{
			Address slimTestReg = fapi.toAddr(0xFFA02);
			byte testReg = fapi.getByte(slimTestReg);
			isY6 = (testReg == Y6cpuType);
		}
		
		mb.setWrite(true);
		mb.setVolatile(true);
		fapi.createLabel(fapi.toAddr(0xFFA00),"SLIMCR",false); fapi.createWord(fapi.toAddr(0xFFA00));
		fapi.createLabel(fapi.toAddr(0xFFA02),"SLIMTR",false); fapi.createWord(fapi.toAddr(0xFFA02));
		fapi.createLabel(fapi.toAddr(0xFFA04),"SYNCR",false); fapi.createWord(fapi.toAddr(0xFFA04));
		fapi.createLabel(fapi.toAddr(0xFFA07),"SLIM_RSR",false); fapi.createByte(fapi.toAddr(0xFFA07));
		fapi.createLabel(fapi.toAddr(0xFFA09),"SLIM_TRE",false); fapi.createByte(fapi.toAddr(0xFFA09));
		fapi.createLabel(fapi.toAddr(0xFFA0A),"MCRC",false); fapi.createWord(fapi.toAddr(0xFFA0A));
		fapi.createLabel(fapi.toAddr(0xFFA0D),"SMD",false); fapi.createByte(fapi.toAddr(0xFFA0D));
		fapi.createLabel(fapi.toAddr(0xFFA0E),"PCON",false); fapi.createWord(fapi.toAddr(0xFFA0E));
		fapi.createLabel(fapi.toAddr(0xFFA10),"PORTA",false); fapi.createByte(fapi.toAddr(0xFFA10));
		fapi.createLabel(fapi.toAddr(0xFFA11),"PORTB",false); fapi.createByte(fapi.toAddr(0xFFA11));
		fapi.createLabel(fapi.toAddr(0xFFA12),"PORTAP",false); fapi.createByte(fapi.toAddr(0xFFA12));
		fapi.createLabel(fapi.toAddr(0xFFA13),"PORTBP",false); fapi.createByte(fapi.toAddr(0xFFA13));
		fapi.createLabel(fapi.toAddr(0xFFA15),"DDRAB",false); fapi.createByte(fapi.toAddr(0xFFA15));
		fapi.createLabel(fapi.toAddr(0xFFA18),"PORTC",false); fapi.createByte(fapi.toAddr(0xFFA18));
		fapi.createLabel(fapi.toAddr(0xFFA19),"PORTD",false); fapi.createByte(fapi.toAddr(0xFFA19));
		fapi.createLabel(fapi.toAddr(0xFFA1A),"PORTCP",false); fapi.createByte(fapi.toAddr(0xFFA1A));
		fapi.createLabel(fapi.toAddr(0xFFA1B),"PORTDP",false); fapi.createByte(fapi.toAddr(0xFFA1B));
		fapi.createLabel(fapi.toAddr(0xFFA1C),"DDRC",false); fapi.createByte(fapi.toAddr(0xFFA1C));
		fapi.createLabel(fapi.toAddr(0xFFA1D),"DDRD",false); fapi.createByte(fapi.toAddr(0xFFA1D));
		fapi.createLabel(fapi.toAddr(0xFFA1E),"PCPAR",false); fapi.createByte(fapi.toAddr(0xFFA1E));
		fapi.createLabel(fapi.toAddr(0xFFA1F),"PDPAR",false); fapi.createByte(fapi.toAddr(0xFFA1F));
		fapi.createLabel(fapi.toAddr(0xFFA21),"PORTE",false); fapi.createByte(fapi.toAddr(0xFFA21));
		fapi.createLabel(fapi.toAddr(0xFFA23),"PORTEP",false); fapi.createByte(fapi.toAddr(0xFFA23));
		fapi.createLabel(fapi.toAddr(0xFFA25),"DDRE",false); fapi.createByte(fapi.toAddr(0xFFA25));
		fapi.createLabel(fapi.toAddr(0xFFA27),"PEPAR",false); fapi.createByte(fapi.toAddr(0xFFA27));
		fapi.createLabel(fapi.toAddr(0xFFA28),"PORTG",false); fapi.createByte(fapi.toAddr(0xFFA28));
		fapi.createLabel(fapi.toAddr(0xFFA29),"PORTH",false); fapi.createByte(fapi.toAddr(0xFFA29));
		fapi.createLabel(fapi.toAddr(0xFFA2A),"PORTGP",false); fapi.createByte(fapi.toAddr(0xFFA2A));
		fapi.createLabel(fapi.toAddr(0xFFA2B),"PORTHP",false); fapi.createByte(fapi.toAddr(0xFFA2B));
		fapi.createLabel(fapi.toAddr(0xFFA2C),"DDRG",false); fapi.createByte(fapi.toAddr(0xFFA2C));
		fapi.createLabel(fapi.toAddr(0xFFA2D),"DDRH",false); fapi.createByte(fapi.toAddr(0xFFA2D));
		fapi.createLabel(fapi.toAddr(0xFFA31),"PORTF",false); fapi.createByte(fapi.toAddr(0xFFA31));
		fapi.createLabel(fapi.toAddr(0xFFA33),"PORTFP",false); fapi.createByte(fapi.toAddr(0xFFA33));
		fapi.createLabel(fapi.toAddr(0xFFA35),"DDRF",false); fapi.createByte(fapi.toAddr(0xFFA35));
		fapi.createLabel(fapi.toAddr(0xFFA36),"PFPAR",false); fapi.createWord(fapi.toAddr(0xFFA36));
		fapi.createLabel(fapi.toAddr(0xFFA39),"PORTFE",false); fapi.createByte(fapi.toAddr(0xFFA39));
		fapi.createLabel(fapi.toAddr(0xFFA3B),"PFEER",false); fapi.createByte(fapi.toAddr(0xFFA3B));
		fapi.createLabel(fapi.toAddr(0xFFA3C),"PFLVR",false); fapi.createByte(fapi.toAddr(0xFFA3C));
		fapi.createLabel(fapi.toAddr(0xFFA3D),"PFIVR",false); fapi.createByte(fapi.toAddr(0xFFA3D));
		fapi.createLabel(fapi.toAddr(0xFFA40),"TSTMSRA",false); fapi.createWord(fapi.toAddr(0xFFA40));
		fapi.createLabel(fapi.toAddr(0xFFA42),"TSTMSRB",false); fapi.createWord(fapi.toAddr(0xFFA42));
		fapi.createLabel(fapi.toAddr(0xFFA44),"TSTSC",false); fapi.createWord(fapi.toAddr(0xFFA44));
		fapi.createLabel(fapi.toAddr(0xFFA46),"TSTRC",false); fapi.createWord(fapi.toAddr(0xFFA46));
		fapi.createLabel(fapi.toAddr(0xFFA48),"CREG",false); fapi.createWord(fapi.toAddr(0xFFA48));
		fapi.createLabel(fapi.toAddr(0xFFA4A),"DREG",false); fapi.createWord(fapi.toAddr(0xFFA4A));
		fapi.createLabel(fapi.toAddr(0xFFA50),"SYPCR",false); fapi.createWord(fapi.toAddr(0xFFA50));
		fapi.createLabel(fapi.toAddr(0xFFA52),"TIC",false); fapi.createByte(fapi.toAddr(0xFFA52));
		fapi.createLabel(fapi.toAddr(0xFFA53),"TIV",false); fapi.createByte(fapi.toAddr(0xFFA53));
		fapi.createLabel(fapi.toAddr(0xFFA55),"SWSR",false); fapi.createByte(fapi.toAddr(0xFFA55));
		fapi.createLabel(fapi.toAddr(0xFFA56),"PRESCALER",false); fapi.createWord(fapi.toAddr(0xFFA56));
		fapi.createLabel(fapi.toAddr(0xFFA58),"SWP",false); fapi.createWord(fapi.toAddr(0xFFA58));
		fapi.createLabel(fapi.toAddr(0xFFA5A),"TIP",false); fapi.createWord(fapi.toAddr(0xFFA5A));
		fapi.createLabel(fapi.toAddr(0xFFA5C),"SWDC",false); fapi.createWord(fapi.toAddr(0xFFA5C));
		fapi.createLabel(fapi.toAddr(0xFFA5E),"RTDC",false); fapi.createWord(fapi.toAddr(0xFFA5E));
		fapi.createLabel(fapi.toAddr(0xFFA60),"CSBARA",false); fapi.createWord(fapi.toAddr(0xFFA60));
		fapi.createLabel(fapi.toAddr(0xFFA62),"CSORA",false); fapi.createWord(fapi.toAddr(0xFFA62));
		fapi.createLabel(fapi.toAddr(0xFFA64),"CSBARB",false); fapi.createWord(fapi.toAddr(0xFFA64));
		fapi.createLabel(fapi.toAddr(0xFFA66),"CSORB",false); fapi.createWord(fapi.toAddr(0xFFA66));
		fapi.createLabel(fapi.toAddr(0xFFA68),"CSBARC",false); fapi.createWord(fapi.toAddr(0xFFA68));
		fapi.createLabel(fapi.toAddr(0xFFA6A),"CSORC",false); fapi.createWord(fapi.toAddr(0xFFA6A));
		fapi.createLabel(fapi.toAddr(0xFFA6C),"CSCR",false); fapi.createWord(fapi.toAddr(0xFFA6C));
		fapi.createLabel(fapi.toAddr(0xFFA73),"L1ICRR",false); fapi.createByte(fapi.toAddr(0xFFA73));
		fapi.createLabel(fapi.toAddr(0xFFA75),"L2ICRR",false); fapi.createByte(fapi.toAddr(0xFFA75));
		fapi.createLabel(fapi.toAddr(0xFFA77),"L3ICRR",false); fapi.createByte(fapi.toAddr(0xFFA77));
		fapi.createLabel(fapi.toAddr(0xFFA79),"L4ICRR",false); fapi.createByte(fapi.toAddr(0xFFA79));
		fapi.createLabel(fapi.toAddr(0xFFA7B),"L5ICRR",false); fapi.createByte(fapi.toAddr(0xFFA7B));
		fapi.createLabel(fapi.toAddr(0xFFA7D),"L6ICRR",false); fapi.createByte(fapi.toAddr(0xFFA7D));
		fapi.createLabel(fapi.toAddr(0xFFA7F),"L7ICRR",false); fapi.createByte(fapi.toAddr(0xFFA7F));
		fapi.createLabel(fapi.toAddr(0xFFA80),"ACSMCR",false); fapi.createWord(fapi.toAddr(0xFFA80));
		fapi.createLabel(fapi.toAddr(0xFFA82),"ACSTR",false); fapi.createWord(fapi.toAddr(0xFFA82));
		fapi.createLabel(fapi.toAddr(0xFFA89),"ACS0DR",false); fapi.createByte(fapi.toAddr(0xFFA89));
		fapi.createLabel(fapi.toAddr(0xFFA8F),"ACSPAR",false); fapi.createByte(fapi.toAddr(0xFFA8F));
		fapi.createLabel(fapi.toAddr(0xFFA90),"ACSBAR0",false); fapi.createWord(fapi.toAddr(0xFFA90));
		fapi.createLabel(fapi.toAddr(0xFFA92),"ACSOR0",false); fapi.createWord(fapi.toAddr(0xFFA92));
		fapi.createLabel(fapi.toAddr(0xFFA94),"ACSBAR1",false); fapi.createWord(fapi.toAddr(0xFFA94));
		fapi.createLabel(fapi.toAddr(0xFFA96),"ACSOR1",false); fapi.createWord(fapi.toAddr(0xFFA96));
		fapi.createLabel(fapi.toAddr(0xFFA98),"ACSBAR2",false); fapi.createWord(fapi.toAddr(0xFFA98));
		fapi.createLabel(fapi.toAddr(0xFFA9A),"ACSOR2",false); fapi.createWord(fapi.toAddr(0xFFA9A));
		fapi.createLabel(fapi.toAddr(0xFFE00),"TPUMCR",false); fapi.createWord(fapi.toAddr(0xFFE00));
		fapi.createLabel(fapi.toAddr(0xFFE02),"TCR",false); fapi.createWord(fapi.toAddr(0xFFE02));
		fapi.createLabel(fapi.toAddr(0xFFE04),"DSCR",false); fapi.createWord(fapi.toAddr(0xFFE04));
		fapi.createLabel(fapi.toAddr(0xFFE06),"DSSR",false); fapi.createWord(fapi.toAddr(0xFFE06));
		fapi.createLabel(fapi.toAddr(0xFFE08),"TICR",false); fapi.createWord(fapi.toAddr(0xFFE08));
		fapi.createLabel(fapi.toAddr(0xFFE0A),"CIER",false); fapi.createWord(fapi.toAddr(0xFFE0A));
		fapi.createLabel(fapi.toAddr(0xFFE0C),"CFSR0",false); fapi.createWord(fapi.toAddr(0xFFE0C));
		fapi.createLabel(fapi.toAddr(0xFFE0E),"CFSR1",false); fapi.createWord(fapi.toAddr(0xFFE0E));
		fapi.createLabel(fapi.toAddr(0xFFE10),"CFSR2",false); fapi.createWord(fapi.toAddr(0xFFE10));
		fapi.createLabel(fapi.toAddr(0xFFE12),"CFSR3",false); fapi.createWord(fapi.toAddr(0xFFE12));
		fapi.createLabel(fapi.toAddr(0xFFE14),"HSQR0",false); fapi.createWord(fapi.toAddr(0xFFE14));
		fapi.createLabel(fapi.toAddr(0xFFE16),"HSQR1",false); fapi.createWord(fapi.toAddr(0xFFE16));
		fapi.createLabel(fapi.toAddr(0xFFE18),"HSRR0",false); fapi.createWord(fapi.toAddr(0xFFE18));
		fapi.createLabel(fapi.toAddr(0xFFE1A),"HSRR1",false); fapi.createWord(fapi.toAddr(0xFFE1A));
		fapi.createLabel(fapi.toAddr(0xFFE1C),"CPR0",false); fapi.createWord(fapi.toAddr(0xFFE1C));
		fapi.createLabel(fapi.toAddr(0xFFE1E),"CPR1",false); fapi.createWord(fapi.toAddr(0xFFE1E));
		fapi.createLabel(fapi.toAddr(0xFFE20),"CISR",false); fapi.createWord(fapi.toAddr(0xFFE20));
		fapi.createLabel(fapi.toAddr(0xFFE22),"LR",false); fapi.createWord(fapi.toAddr(0xFFE22));
		fapi.createLabel(fapi.toAddr(0xFFE24),"SGLR",false); fapi.createWord(fapi.toAddr(0xFFE24));
		fapi.createLabel(fapi.toAddr(0xFFE26),"DCNR",false); fapi.createWord(fapi.toAddr(0xFFE26));
		fapi.createLabel(fapi.toAddr(0xFFE28),"TPUMCR2",false); fapi.createWord(fapi.toAddr(0xFFE28));
		fapi.createLabel(fapi.toAddr(0xFF900),"BIUMCR",false); fapi.createWord(fapi.toAddr(0xFF900));
		fapi.createLabel(fapi.toAddr(0xFF902),"BIUTEST",false); fapi.createWord(fapi.toAddr(0xFF902));
		fapi.createLabel(fapi.toAddr(0xFF904),"BIUTBR",false); fapi.createWord(fapi.toAddr(0xFF904));
		fapi.createLabel(fapi.toAddr(0xFF908),"CPCR",false); fapi.createWord(fapi.toAddr(0xFF908));
		fapi.createLabel(fapi.toAddr(0xFF90A),"CPTR",false); fapi.createWord(fapi.toAddr(0xFF90A));
		fapi.createLabel(fapi.toAddr(0xFF910),"MCSMSIC2",false); fapi.createWord(fapi.toAddr(0xFF910));
		fapi.createLabel(fapi.toAddr(0xFF912),"MCSMCNT2",false); fapi.createWord(fapi.toAddr(0xFF912));
		fapi.createLabel(fapi.toAddr(0xFF914),"MCSMML2",false); fapi.createWord(fapi.toAddr(0xFF914));
		fapi.createLabel(fapi.toAddr(0xFF918),"DASMISC3",false); fapi.createWord(fapi.toAddr(0xFF918));
		fapi.createLabel(fapi.toAddr(0xFF91A),"DASMA3",false); fapi.createWord(fapi.toAddr(0xFF91A));
		fapi.createLabel(fapi.toAddr(0xFF91C),"DASMB3",false); fapi.createWord(fapi.toAddr(0xFF91C));
		fapi.createLabel(fapi.toAddr(0xFF920),"DASMISC4",false); fapi.createWord(fapi.toAddr(0xFF920));
		fapi.createLabel(fapi.toAddr(0xFF922),"DASMA4",false); fapi.createWord(fapi.toAddr(0xFF922));
		fapi.createLabel(fapi.toAddr(0xFF924),"DASMB4",false); fapi.createWord(fapi.toAddr(0xFF924));
		fapi.createLabel(fapi.toAddr(0xFF928),"DASMISC5",false); fapi.createWord(fapi.toAddr(0xFF928));
		fapi.createLabel(fapi.toAddr(0xFF92A),"DASMA5",false); fapi.createWord(fapi.toAddr(0xFF92A));
		fapi.createLabel(fapi.toAddr(0xFF92C),"DASMB5",false); fapi.createWord(fapi.toAddr(0xFF92C));
		fapi.createLabel(fapi.toAddr(0xFF930),"DASMISC6",false); fapi.createWord(fapi.toAddr(0xFF930));
		fapi.createLabel(fapi.toAddr(0xFF932),"DASMA6",false); fapi.createWord(fapi.toAddr(0xFF932));
		fapi.createLabel(fapi.toAddr(0xFF934),"DASMB6",false); fapi.createWord(fapi.toAddr(0xFF934));
		fapi.createLabel(fapi.toAddr(0xFF938),"DASMISC7",false); fapi.createWord(fapi.toAddr(0xFF938));
		fapi.createLabel(fapi.toAddr(0xFF93A),"DASMA7",false); fapi.createWord(fapi.toAddr(0xFF93A));
		fapi.createLabel(fapi.toAddr(0xFF93C),"DASMB7",false); fapi.createWord(fapi.toAddr(0xFF93C));
		fapi.createLabel(fapi.toAddr(0xFF940),"DASMISC8",false); fapi.createWord(fapi.toAddr(0xFF940));
		fapi.createLabel(fapi.toAddr(0xFF942),"DASMA8",false); fapi.createWord(fapi.toAddr(0xFF942));
		fapi.createLabel(fapi.toAddr(0xFF944),"DASMB8",false); fapi.createWord(fapi.toAddr(0xFF944));
		fapi.createLabel(fapi.toAddr(0xFF948),"PWMSIC9",false); fapi.createWord(fapi.toAddr(0xFF948));
		fapi.createLabel(fapi.toAddr(0xFF94A),"PWMA9",false); fapi.createWord(fapi.toAddr(0xFF94A));
		fapi.createLabel(fapi.toAddr(0xFF94C),"PWMB9",false); fapi.createWord(fapi.toAddr(0xFF94C));
		fapi.createLabel(fapi.toAddr(0xFF94E),"PWMC9",false); fapi.createWord(fapi.toAddr(0xFF94E));
		fapi.createLabel(fapi.toAddr(0xFF950),"PWMSIC10",false); fapi.createWord(fapi.toAddr(0xFF950));
		fapi.createLabel(fapi.toAddr(0xFF952),"PWMA10",false); fapi.createWord(fapi.toAddr(0xFF952));
		fapi.createLabel(fapi.toAddr(0xFF954),"PWMB10",false); fapi.createWord(fapi.toAddr(0xFF954));
		fapi.createLabel(fapi.toAddr(0xFF956),"PWMC10",false); fapi.createWord(fapi.toAddr(0xFF956));
		fapi.createLabel(fapi.toAddr(0xFF958),"PWMSIC11",false); fapi.createWord(fapi.toAddr(0xFF958));
		fapi.createLabel(fapi.toAddr(0xFF95A),"PWMA11",false); fapi.createWord(fapi.toAddr(0xFF95A));
		fapi.createLabel(fapi.toAddr(0xFF95C),"PWMB11",false); fapi.createWord(fapi.toAddr(0xFF95C));
		fapi.createLabel(fapi.toAddr(0xFF95E),"PWMC11",false); fapi.createWord(fapi.toAddr(0xFF95E));
		fapi.createLabel(fapi.toAddr(0xFF960),"PWMSIC12",false); fapi.createWord(fapi.toAddr(0xFF960));
		fapi.createLabel(fapi.toAddr(0xFF962),"PWMA12",false); fapi.createWord(fapi.toAddr(0xFF962));
		fapi.createLabel(fapi.toAddr(0xFF964),"PWMB12",false); fapi.createWord(fapi.toAddr(0xFF964));
		fapi.createLabel(fapi.toAddr(0xFF966),"PWMC12",false); fapi.createWord(fapi.toAddr(0xFF966));
		fapi.createLabel(fapi.toAddr(0xFF968),"PWMSIC13",false); fapi.createWord(fapi.toAddr(0xFF968));
		fapi.createLabel(fapi.toAddr(0xFF96A),"PWMA13",false); fapi.createWord(fapi.toAddr(0xFF96A));
		fapi.createLabel(fapi.toAddr(0xFF96C),"PWMB13",false); fapi.createWord(fapi.toAddr(0xFF96C));
		fapi.createLabel(fapi.toAddr(0xFF96E),"PWMC13",false); fapi.createWord(fapi.toAddr(0xFF96E));
		fapi.createLabel(fapi.toAddr(0xFF970),"DASMISC14",false); fapi.createWord(fapi.toAddr(0xFF970));
		fapi.createLabel(fapi.toAddr(0xFF972),"DASMA14",false); fapi.createWord(fapi.toAddr(0xFF972));
		fapi.createLabel(fapi.toAddr(0xFF974),"DASMB14",false); fapi.createWord(fapi.toAddr(0xFF974));
		fapi.createLabel(fapi.toAddr(0xFF978),"DASMISC15",false); fapi.createWord(fapi.toAddr(0xFF978));
		fapi.createLabel(fapi.toAddr(0xFF97A),"DASMA15",false); fapi.createWord(fapi.toAddr(0xFF97A));
		fapi.createLabel(fapi.toAddr(0xFF97C),"DASMB15",false); fapi.createWord(fapi.toAddr(0xFF97C));
		fapi.createLabel(fapi.toAddr(0xFF980),"DASMISC16",false); fapi.createWord(fapi.toAddr(0xFF980));
		fapi.createLabel(fapi.toAddr(0xFF982),"DASMA16",false); fapi.createWord(fapi.toAddr(0xFF982));
		fapi.createLabel(fapi.toAddr(0xFF984),"DASMB16",false); fapi.createWord(fapi.toAddr(0xFF984));
		fapi.createLabel(fapi.toAddr(0xFF988),"DASMISC17",false); fapi.createWord(fapi.toAddr(0xFF988));
		fapi.createLabel(fapi.toAddr(0xFF98A),"DASMA17",false); fapi.createWord(fapi.toAddr(0xFF98A));
		fapi.createLabel(fapi.toAddr(0xFF98C),"DASMB17",false); fapi.createWord(fapi.toAddr(0xFF98C));
		fapi.createLabel(fapi.toAddr(0xFF990),"DASMISC18",false); fapi.createWord(fapi.toAddr(0xFF990));
		fapi.createLabel(fapi.toAddr(0xFF992),"DASMA18",false); fapi.createWord(fapi.toAddr(0xFF992));
		fapi.createLabel(fapi.toAddr(0xFF994),"DASMB18",false); fapi.createWord(fapi.toAddr(0xFF994));
		fapi.createLabel(fapi.toAddr(0xFF998),"MCSMISC19",false); fapi.createWord(fapi.toAddr(0xFF998));
		fapi.createLabel(fapi.toAddr(0xFF99A),"MCSMCNT19",false); fapi.createWord(fapi.toAddr(0xFF99A));
		fapi.createLabel(fapi.toAddr(0xFF99C),"MCSMML19",false); fapi.createWord(fapi.toAddr(0xFF99C));
		fapi.createLabel(fapi.toAddr(0xFF9A0),"DASMISC20",false); fapi.createWord(fapi.toAddr(0xFF9A0));
		fapi.createLabel(fapi.toAddr(0xFF9A2),"DASMA20",false); fapi.createWord(fapi.toAddr(0xFF9A2));
		fapi.createLabel(fapi.toAddr(0xFF9A4),"DASMB20",false); fapi.createWord(fapi.toAddr(0xFF9A4));
		fapi.createLabel(fapi.toAddr(0xFF9A8),"MCSMISC21",false); fapi.createWord(fapi.toAddr(0xFF9A8));
		fapi.createLabel(fapi.toAddr(0xFF9AA),"MCSMCNT21",false); fapi.createWord(fapi.toAddr(0xFF9AA));
		fapi.createLabel(fapi.toAddr(0xFF9AC),"MCSMML21",false); fapi.createWord(fapi.toAddr(0xFF9AC));
		fapi.createLabel(fapi.toAddr(0xFF9B0),"DASMISC22",false); fapi.createWord(fapi.toAddr(0xFF9B0));
		fapi.createLabel(fapi.toAddr(0xFF9B2),"DASMA22",false); fapi.createWord(fapi.toAddr(0xFF9B2));
		fapi.createLabel(fapi.toAddr(0xFF9B4),"DASMB22",false); fapi.createWord(fapi.toAddr(0xFF9B4));
		fapi.createLabel(fapi.toAddr(0xFF9B8),"MCSMISC23",false); fapi.createWord(fapi.toAddr(0xFF9B8));
		fapi.createLabel(fapi.toAddr(0xFF9BA),"MCSMCNT23",false); fapi.createWord(fapi.toAddr(0xFF9BA));
		fapi.createLabel(fapi.toAddr(0xFF9BC),"MCSMML23",false); fapi.createWord(fapi.toAddr(0xFF9BC));
		fapi.createLabel(fapi.toAddr(0xFF200),"QADCMCR",false); fapi.createWord(fapi.toAddr(0xFF200));
		fapi.createLabel(fapi.toAddr(0xFF202),"QADCTEST",false); fapi.createWord(fapi.toAddr(0xFF202));
		fapi.createLabel(fapi.toAddr(0xFF204),"QADCINT",false); fapi.createWord(fapi.toAddr(0xFF204));
		fapi.createLabel(fapi.toAddr(0xFF206),"PORTQA",false); fapi.createByte(fapi.toAddr(0xFF206));
		fapi.createLabel(fapi.toAddr(0xFF207),"PORTQB",false); fapi.createByte(fapi.toAddr(0xFF207));
		fapi.createLabel(fapi.toAddr(0xFF208),"DDRQA",false); fapi.createWord(fapi.toAddr(0xFF208));
		fapi.createLabel(fapi.toAddr(0xFF20A),"QACR0",false); fapi.createWord(fapi.toAddr(0xFF20A));
		fapi.createLabel(fapi.toAddr(0xFF20C),"QACR1",false); fapi.createWord(fapi.toAddr(0xFF20C));
		fapi.createLabel(fapi.toAddr(0xFF20E),"QACR2",false); fapi.createWord(fapi.toAddr(0xFF20E));
		fapi.createLabel(fapi.toAddr(0xFF210),"QASR",false); fapi.createWord(fapi.toAddr(0xFF210));
		
		fapi.createLabel(fapi.toAddr(0xFF230),"CCWtable",false);
		fapi.createData(fapi.toAddr(0xFF230),new ArrayDataType(new WordDataType(),40,2));
		
		fapi.createLabel(fapi.toAddr(0xFF2B0),"RJURRtable",false);
		fapi.createData(fapi.toAddr(0xFF2B0),new ArrayDataType(new WordDataType(),40,2));
		
		fapi.createLabel(fapi.toAddr(0xFF330),"LJSRRtable",false);
		fapi.createData(fapi.toAddr(0xFF330),new ArrayDataType(new WordDataType(),40,2));
		
		fapi.createLabel(fapi.toAddr(0xFF3B0),"LJURRtable",false);
		fapi.createData(fapi.toAddr(0xFF3B0),new ArrayDataType(new WordDataType(),40,2));
		
		fapi.createLabel(fapi.toAddr(0xFF600),"RSMCR",false); fapi.createWord(fapi.toAddr(0xFF600));
		fapi.createLabel(fapi.toAddr(0xFF602),"RSTEST",false); fapi.createWord(fapi.toAddr(0xFF602));
		fapi.createLabel(fapi.toAddr(0xFF604),"RSILR",false); fapi.createByte(fapi.toAddr(0xFF604));
		fapi.createLabel(fapi.toAddr(0xFF605),"RSIVR",false); fapi.createByte(fapi.toAddr(0xFF605));
		fapi.createLabel(fapi.toAddr(0xFF606),"RSRBAR",false); fapi.createWord(fapi.toAddr(0xFF606));
		fapi.createLabel(fapi.toAddr(0xFF610),"RSPAR/RSDDR",false); fapi.createByte(fapi.toAddr(0xFF610));
		fapi.createLabel(fapi.toAddr(0xFF611),"RSPDR",false); fapi.createByte(fapi.toAddr(0xFF611));
		fapi.createLabel(fapi.toAddr(0xFF612),"RSCR0",false); fapi.createWord(fapi.toAddr(0xFF612));
		fapi.createLabel(fapi.toAddr(0xFF614),"RSCR1",false); fapi.createWord(fapi.toAddr(0xFF614));
		fapi.createLabel(fapi.toAddr(0xFF616),"RSCR2",false); fapi.createWord(fapi.toAddr(0xFF616));
		fapi.createLabel(fapi.toAddr(0xFF618),"RSCR3",false); fapi.createWord(fapi.toAddr(0xFF618));
		fapi.createLabel(fapi.toAddr(0xFF61A),"RSCMD",false); fapi.createWord(fapi.toAddr(0xFF61A));
		fapi.createLabel(fapi.toAddr(0xFF61C),"RSIX0",false); fapi.createWord(fapi.toAddr(0xFF61C));
		fapi.createLabel(fapi.toAddr(0xFF61E),"RSIX1",false); fapi.createWord(fapi.toAddr(0xFF61E));
		fapi.createLabel(fapi.toAddr(0xFF620),"RSIX2",false); fapi.createWord(fapi.toAddr(0xFF620));
		fapi.createLabel(fapi.toAddr(0xFF622),"RSIX3",false); fapi.createWord(fapi.toAddr(0xFF622));
		fapi.createLabel(fapi.toAddr(0xFF624),"RSIX4",false); fapi.createWord(fapi.toAddr(0xFF624));
		fapi.createLabel(fapi.toAddr(0xFF626),"RSIX5",false); fapi.createWord(fapi.toAddr(0xFF626));
		fapi.createLabel(fapi.toAddr(0xFF628),"RSSR",false); fapi.createWord(fapi.toAddr(0xFF628));
		fapi.createLabel(fapi.toAddr(0xFF62A),"RSBC0",false); fapi.createWord(fapi.toAddr(0xFF62A));
		fapi.createLabel(fapi.toAddr(0xFF62C),"RSBC1",false); fapi.createWord(fapi.toAddr(0xFF62C));
		fapi.createLabel(fapi.toAddr(0xFF62E),"RSSFT",false); fapi.createWord(fapi.toAddr(0xFF62E));
		fapi.createLabel(fapi.toAddr(0xFF630),"RSLTST",false); fapi.createWord(fapi.toAddr(0xFF630));
		fapi.createLabel(fapi.toAddr(0xFF638),"RSCSPAR/RSCSDDR",false); fapi.createByte(fapi.toAddr(0xFF638));
		fapi.createLabel(fapi.toAddr(0xFF639),"RSCSPDR",false); fapi.createByte(fapi.toAddr(0xFF639));
		fapi.createLabel(fapi.toAddr(0xFFC00),"MMCR",false); fapi.createWord(fapi.toAddr(0xFFC00));
		fapi.createLabel(fapi.toAddr(0xFFC02),"MTEST",false); fapi.createWord(fapi.toAddr(0xFFC02));
		fapi.createLabel(fapi.toAddr(0xFFC04),"ILSCI",false); fapi.createByte(fapi.toAddr(0xFFC04));
		fapi.createLabel(fapi.toAddr(0xFFC05),"MIVR",false); fapi.createByte(fapi.toAddr(0xFFC05));
		fapi.createLabel(fapi.toAddr(0xFFC06),"ILSPI",false); fapi.createByte(fapi.toAddr(0xFFC06));
		fapi.createLabel(fapi.toAddr(0xFFC09),"PMCPAR",false); fapi.createByte(fapi.toAddr(0xFFC09));
		fapi.createLabel(fapi.toAddr(0xFFC0B),"DDRMC",false); fapi.createByte(fapi.toAddr(0xFFC0B));
		fapi.createLabel(fapi.toAddr(0xFFC0D),"PORTMC",false); fapi.createByte(fapi.toAddr(0xFFC0D));
		fapi.createLabel(fapi.toAddr(0xFFC0F),"PORTMCP",false); fapi.createByte(fapi.toAddr(0xFFC0F));
		fapi.createLabel(fapi.toAddr(0xFFC18),"SCCR0A",false); fapi.createWord(fapi.toAddr(0xFFC18));
		fapi.createLabel(fapi.toAddr(0xFFC1A),"SCCR1A",false); fapi.createWord(fapi.toAddr(0xFFC1A));
		fapi.createLabel(fapi.toAddr(0xFFC1C),"SCSRA",false); fapi.createWord(fapi.toAddr(0xFFC1C));
		fapi.createLabel(fapi.toAddr(0xFFC1E),"SCDRA",false); fapi.createWord(fapi.toAddr(0xFFC1E));
		fapi.createLabel(fapi.toAddr(0xFFC28),"SCCR0B",false); fapi.createWord(fapi.toAddr(0xFFC28));
		fapi.createLabel(fapi.toAddr(0xFFC2A),"SCCR1B",false); fapi.createWord(fapi.toAddr(0xFFC2A));
		fapi.createLabel(fapi.toAddr(0xFFC2C),"SCSRB",false); fapi.createWord(fapi.toAddr(0xFFC2C));
		fapi.createLabel(fapi.toAddr(0xFFC2E),"SCDRB",false); fapi.createWord(fapi.toAddr(0xFFC2E));
		fapi.createLabel(fapi.toAddr(0xFFC38),"SPCR",false); fapi.createWord(fapi.toAddr(0xFFC38));
		fapi.createLabel(fapi.toAddr(0xFFC3C),"SPSR",false); fapi.createWord(fapi.toAddr(0xFFC3C));
		fapi.createLabel(fapi.toAddr(0xFFC3E),"SPDR",false); fapi.createWord(fapi.toAddr(0xFFC3E));
		
		if (isY6)
		{
			fapi.createLabel(fapi.toAddr(0xFF780),"HDF1MCR",false); fapi.createWord(fapi.toAddr(0xFF7C0));
			fapi.createLabel(fapi.toAddr(0xFF782),"HDF1TST",false); fapi.createWord(fapi.toAddr(0xFF7C2));
			fapi.createLabel(fapi.toAddr(0xFF784),"HDF1BAH",false); fapi.createWord(fapi.toAddr(0xFF7C4));
			fapi.createLabel(fapi.toAddr(0xFF786),"HDF1BAL",false); fapi.createWord(fapi.toAddr(0xFF7C6));
			fapi.createLabel(fapi.toAddr(0xFF788),"HDF1CTL",false); fapi.createWord(fapi.toAddr(0xFF7C8));
			fapi.createLabel(fapi.toAddr(0xFF790),"HDF1BS0",false); fapi.createWord(fapi.toAddr(0xFF7D0));
			fapi.createLabel(fapi.toAddr(0xFF792),"HDF1BS1",false); fapi.createWord(fapi.toAddr(0xFF7D2));
			fapi.createLabel(fapi.toAddr(0xFF794),"HDF1BS2",false); fapi.createWord(fapi.toAddr(0xFF7D4));
			fapi.createLabel(fapi.toAddr(0xFF796),"HDF1BS3",false); fapi.createWord(fapi.toAddr(0xFF7D6));
			fapi.createLabel(fapi.toAddr(0xFF7C0),"HDF2MCR",false); fapi.createWord(fapi.toAddr(0xFF7E0));
			fapi.createLabel(fapi.toAddr(0xFF7C2),"HDF2TST",false); fapi.createWord(fapi.toAddr(0xFF7E2));
			fapi.createLabel(fapi.toAddr(0xFF7C4),"HDF2BAH",false); fapi.createWord(fapi.toAddr(0xFF7E4));
			fapi.createLabel(fapi.toAddr(0xFF7C6),"HDF2BAL",false); fapi.createWord(fapi.toAddr(0xFF7E6));
			fapi.createLabel(fapi.toAddr(0xFF7C8),"HDF2CTL",false); fapi.createWord(fapi.toAddr(0xFF7E8));
			fapi.createLabel(fapi.toAddr(0xFF7D0),"HDF2BS0",false); fapi.createWord(fapi.toAddr(0xFF7F0));
			fapi.createLabel(fapi.toAddr(0xFF7D2),"HDF2BS1",false); fapi.createWord(fapi.toAddr(0xFF7F2));
			fapi.createLabel(fapi.toAddr(0xFF7D4),"HDF2BS2",false); fapi.createWord(fapi.toAddr(0xFF7F4));
			fapi.createLabel(fapi.toAddr(0xFF7D6),"HDF2BS3",false); fapi.createWord(fapi.toAddr(0xFF7F6));
			fapi.createLabel(fapi.toAddr(0xFF800),"HDF3MCR",false); fapi.createWord(fapi.toAddr(0xFF800));
			fapi.createLabel(fapi.toAddr(0xFF802),"HDF3TST",false); fapi.createWord(fapi.toAddr(0xFF802));
			fapi.createLabel(fapi.toAddr(0xFF804),"HDF3BAH",false); fapi.createWord(fapi.toAddr(0xFF804));
			fapi.createLabel(fapi.toAddr(0xFF806),"HDF3BAL",false); fapi.createWord(fapi.toAddr(0xFF806));
			fapi.createLabel(fapi.toAddr(0xFF808),"HDF3CTL",false); fapi.createWord(fapi.toAddr(0xFF808));
			fapi.createLabel(fapi.toAddr(0xFF810),"HDF3BS0",false); fapi.createWord(fapi.toAddr(0xFF810));
			fapi.createLabel(fapi.toAddr(0xFF812),"HDF3BS1",false); fapi.createWord(fapi.toAddr(0xFF812));
			fapi.createLabel(fapi.toAddr(0xFF814),"HDF3BS2",false); fapi.createWord(fapi.toAddr(0xFF814));
			fapi.createLabel(fapi.toAddr(0xFF816),"HDF3BS3",false); fapi.createWord(fapi.toAddr(0xFF816));
		}
		else
		{
			fapi.createLabel(fapi.toAddr(0xFF7C0),"FEE1MCR",false); fapi.createWord(fapi.toAddr(0xFF7C0));
			fapi.createLabel(fapi.toAddr(0xFF7C2),"FEE1TST",false); fapi.createWord(fapi.toAddr(0xFF7C2));
			fapi.createLabel(fapi.toAddr(0xFF7C4),"FEE1BAH",false); fapi.createWord(fapi.toAddr(0xFF7C4));
			fapi.createLabel(fapi.toAddr(0xFF7C6),"FEE1BAL",false); fapi.createWord(fapi.toAddr(0xFF7C6));
			fapi.createLabel(fapi.toAddr(0xFF7C8),"FEE1CTL",false); fapi.createWord(fapi.toAddr(0xFF7C8));
			fapi.createLabel(fapi.toAddr(0xFF7D0),"FEE1BS0",false); fapi.createWord(fapi.toAddr(0xFF7D0));
			fapi.createLabel(fapi.toAddr(0xFF7D2),"FEE1BS1",false); fapi.createWord(fapi.toAddr(0xFF7D2));
			fapi.createLabel(fapi.toAddr(0xFF7D4),"FEE1BS2",false); fapi.createWord(fapi.toAddr(0xFF7D4));
			fapi.createLabel(fapi.toAddr(0xFF7D6),"FEE1BS3",false); fapi.createWord(fapi.toAddr(0xFF7D6));
			
			fapi.createLabel(fapi.toAddr(0xFF7E0),"FEE2MCR",false); fapi.createWord(fapi.toAddr(0xFF7C0));
			fapi.createLabel(fapi.toAddr(0xFF7E2),"FEE2TST",false); fapi.createWord(fapi.toAddr(0xFF7C2));
			fapi.createLabel(fapi.toAddr(0xFF7E4),"FEE2BAH",false); fapi.createWord(fapi.toAddr(0xFF7C4));
			fapi.createLabel(fapi.toAddr(0xFF7E6),"FEE2BAL",false); fapi.createWord(fapi.toAddr(0xFF7C6));
			fapi.createLabel(fapi.toAddr(0xFF7E8),"FEE2CTL",false); fapi.createWord(fapi.toAddr(0xFF7C8));
			fapi.createLabel(fapi.toAddr(0xFF7F0),"FEE2BS0",false); fapi.createWord(fapi.toAddr(0xFF7D0));
			fapi.createLabel(fapi.toAddr(0xFF7F2),"FEE2BS1",false); fapi.createWord(fapi.toAddr(0xFF7D2));
			fapi.createLabel(fapi.toAddr(0xFF7F4),"FEE2BS2",false); fapi.createWord(fapi.toAddr(0xFF7D4));
			fapi.createLabel(fapi.toAddr(0xFF7F6),"FEE2BS3",false); fapi.createWord(fapi.toAddr(0xFF7D6));

			fapi.createLabel(fapi.toAddr(0xFF800),"FEE3MCR",false); fapi.createWord(fapi.toAddr(0xFF7C0));
			fapi.createLabel(fapi.toAddr(0xFF802),"FEE3TST",false); fapi.createWord(fapi.toAddr(0xFF7C2));
			fapi.createLabel(fapi.toAddr(0xFF804),"FEE3BAH",false); fapi.createWord(fapi.toAddr(0xFF7C4));
			fapi.createLabel(fapi.toAddr(0xFF806),"FEE3BAL",false); fapi.createWord(fapi.toAddr(0xFF7C6));
			fapi.createLabel(fapi.toAddr(0xFF808),"FEE3CTL",false); fapi.createWord(fapi.toAddr(0xFF7C8));
			fapi.createLabel(fapi.toAddr(0xFF810),"FEE3BS0",false); fapi.createWord(fapi.toAddr(0xFF7D0));
			fapi.createLabel(fapi.toAddr(0xFF812),"FEE3BS1",false); fapi.createWord(fapi.toAddr(0xFF7D2));
			fapi.createLabel(fapi.toAddr(0xFF814),"FEE3BS2",false); fapi.createWord(fapi.toAddr(0xFF7D4));
			fapi.createLabel(fapi.toAddr(0xFF816),"FEE3BS3",false); fapi.createWord(fapi.toAddr(0xFF7D6));

			fapi.createLabel(fapi.toAddr(0xFF820),"FEE4MCR",false); fapi.createWord(fapi.toAddr(0xFF7C0));
			fapi.createLabel(fapi.toAddr(0xFF822),"FEE4TST",false); fapi.createWord(fapi.toAddr(0xFF7C2));
			fapi.createLabel(fapi.toAddr(0xFF824),"FEE4BAH",false); fapi.createWord(fapi.toAddr(0xFF7C4));
			fapi.createLabel(fapi.toAddr(0xFF826),"FEE4BAL",false); fapi.createWord(fapi.toAddr(0xFF7C6));
			fapi.createLabel(fapi.toAddr(0xFF828),"FEE4CTL",false); fapi.createWord(fapi.toAddr(0xFF7C8));
			fapi.createLabel(fapi.toAddr(0xFF830),"FEE4BS0",false); fapi.createWord(fapi.toAddr(0xFF7D0));
			fapi.createLabel(fapi.toAddr(0xFF832),"FEE4BS1",false); fapi.createWord(fapi.toAddr(0xFF7D2));
			fapi.createLabel(fapi.toAddr(0xFF834),"FEE4BS2",false); fapi.createWord(fapi.toAddr(0xFF7D4));
			fapi.createLabel(fapi.toAddr(0xFF836),"FEE4BS3",false); fapi.createWord(fapi.toAddr(0xFF7D6));

			fapi.createLabel(fapi.toAddr(0xFF840),"FEE5MCR",false); fapi.createWord(fapi.toAddr(0xFF7C0));
			fapi.createLabel(fapi.toAddr(0xFF842),"FEE5TST",false); fapi.createWord(fapi.toAddr(0xFF7C2));
			fapi.createLabel(fapi.toAddr(0xFF844),"FEE5BAH",false); fapi.createWord(fapi.toAddr(0xFF7C4));
			fapi.createLabel(fapi.toAddr(0xFF846),"FEE5BAL",false); fapi.createWord(fapi.toAddr(0xFF7C6));
			fapi.createLabel(fapi.toAddr(0xFF848),"FEE5CTL",false); fapi.createWord(fapi.toAddr(0xFF7C8));
			fapi.createLabel(fapi.toAddr(0xFF850),"FEE5BS0",false); fapi.createWord(fapi.toAddr(0xFF7D0));
			fapi.createLabel(fapi.toAddr(0xFF852),"FEE5BS1",false); fapi.createWord(fapi.toAddr(0xFF7D2));
			fapi.createLabel(fapi.toAddr(0xFF854),"FEE5BS2",false); fapi.createWord(fapi.toAddr(0xFF7D4));
			fapi.createLabel(fapi.toAddr(0xFF856),"FEE5BS3",false); fapi.createWord(fapi.toAddr(0xFF7D6));
		}
		
		fapi.createLabel(fapi.toAddr(0xFF860),"TFMCR",false); fapi.createWord(fapi.toAddr(0xFF860));
		fapi.createLabel(fapi.toAddr(0xFF862),"TFTST",false); fapi.createWord(fapi.toAddr(0xFF862));
		fapi.createLabel(fapi.toAddr(0xFF864),"TFBAH",false); fapi.createWord(fapi.toAddr(0xFF864));
		fapi.createLabel(fapi.toAddr(0xFF866),"TFBAL",false); fapi.createWord(fapi.toAddr(0xFF866));
		fapi.createLabel(fapi.toAddr(0xFF868),"TFCTL",false); fapi.createWord(fapi.toAddr(0xFF868));
		fapi.createLabel(fapi.toAddr(0xFF870),"TFBS0",false); fapi.createWord(fapi.toAddr(0xFF870));
		fapi.createLabel(fapi.toAddr(0xFF872),"TFBS1",false); fapi.createWord(fapi.toAddr(0xFF872));
		fapi.createLabel(fapi.toAddr(0xFF874),"TFBS2",false); fapi.createWord(fapi.toAddr(0xFF874));
		fapi.createLabel(fapi.toAddr(0xFF876),"TFBS3",false); fapi.createWord(fapi.toAddr(0xFF876));
		fapi.createLabel(fapi.toAddr(0xFFB00),"SRAMMCR",false); fapi.createWord(fapi.toAddr(0xFFB00));
		fapi.createLabel(fapi.toAddr(0xFFB02),"SRAMTST",false); fapi.createWord(fapi.toAddr(0xFFB02));
		fapi.createLabel(fapi.toAddr(0xFFB04),"SRAMBAH",false); fapi.createWord(fapi.toAddr(0xFFB04));
		fapi.createLabel(fapi.toAddr(0xFFB06),"SRAMBAL",false); fapi.createWord(fapi.toAddr(0xFFB06));
		fapi.createLabel(fapi.toAddr(0xFFF00),"TPUCh0Par0",false); fapi.createWord(fapi.toAddr(0xFFF00));
		fapi.createLabel(fapi.toAddr(0xFFF02),"TPUCh0Par1",false); fapi.createWord(fapi.toAddr(0xFFF02));
		fapi.createLabel(fapi.toAddr(0xFFF04),"TPUCh0Par2",false); fapi.createWord(fapi.toAddr(0xFFF04));
		fapi.createLabel(fapi.toAddr(0xFFF06),"TPUCh0Par3",false); fapi.createWord(fapi.toAddr(0xFFF06));
		fapi.createLabel(fapi.toAddr(0xFFF08),"TPUCh0Par4",false); fapi.createWord(fapi.toAddr(0xFFF08));
		fapi.createLabel(fapi.toAddr(0xFFF0A),"TPUCh0Par5",false); fapi.createWord(fapi.toAddr(0xFFF0A));
		fapi.createLabel(fapi.toAddr(0xFFF0C),"TPUCh0Par6",false); fapi.createWord(fapi.toAddr(0xFFF0C));
		fapi.createLabel(fapi.toAddr(0xFFF0E),"TPUCh0Par7",false); fapi.createWord(fapi.toAddr(0xFFF0E));
		fapi.createLabel(fapi.toAddr(0xFFF10),"TPUCh1Par0",false); fapi.createWord(fapi.toAddr(0xFFF10));
		fapi.createLabel(fapi.toAddr(0xFFF12),"TPUCh1Par1",false); fapi.createWord(fapi.toAddr(0xFFF12));
		fapi.createLabel(fapi.toAddr(0xFFF14),"TPUCh1Par2",false); fapi.createWord(fapi.toAddr(0xFFF14));
		fapi.createLabel(fapi.toAddr(0xFFF16),"TPUCh1Par3",false); fapi.createWord(fapi.toAddr(0xFFF16));
		fapi.createLabel(fapi.toAddr(0xFFF18),"TPUCh1Par4",false); fapi.createWord(fapi.toAddr(0xFFF18));
		fapi.createLabel(fapi.toAddr(0xFFF1A),"TPUCh1Par5",false); fapi.createWord(fapi.toAddr(0xFFF1A));
		fapi.createLabel(fapi.toAddr(0xFFF1C),"TPUCh1Par6",false); fapi.createWord(fapi.toAddr(0xFFF1C));
		fapi.createLabel(fapi.toAddr(0xFFF1E),"TPUCh1Par7",false); fapi.createWord(fapi.toAddr(0xFFF1E));
		fapi.createLabel(fapi.toAddr(0xFFF20),"TPUCh2Par0",false); fapi.createWord(fapi.toAddr(0xFFF20));
		fapi.createLabel(fapi.toAddr(0xFFF22),"TPUCh2Par1",false); fapi.createWord(fapi.toAddr(0xFFF22));
		fapi.createLabel(fapi.toAddr(0xFFF24),"TPUCh2Par2",false); fapi.createWord(fapi.toAddr(0xFFF24));
		fapi.createLabel(fapi.toAddr(0xFFF26),"TPUCh2Par3",false); fapi.createWord(fapi.toAddr(0xFFF26));
		fapi.createLabel(fapi.toAddr(0xFFF28),"TPUCh2Par4",false); fapi.createWord(fapi.toAddr(0xFFF28));
		fapi.createLabel(fapi.toAddr(0xFFF2A),"TPUCh2Par5",false); fapi.createWord(fapi.toAddr(0xFFF2A));
		fapi.createLabel(fapi.toAddr(0xFFF2C),"TPUCh2Par6",false); fapi.createWord(fapi.toAddr(0xFFF2C));
		fapi.createLabel(fapi.toAddr(0xFFF2E),"TPUCh2Par7",false); fapi.createWord(fapi.toAddr(0xFFF2E));
		fapi.createLabel(fapi.toAddr(0xFFF30),"TPUCh3Par0",false); fapi.createWord(fapi.toAddr(0xFFF30));
		fapi.createLabel(fapi.toAddr(0xFFF32),"TPUCh3Par1",false); fapi.createWord(fapi.toAddr(0xFFF32));
		fapi.createLabel(fapi.toAddr(0xFFF34),"TPUCh3Par2",false); fapi.createWord(fapi.toAddr(0xFFF34));
		fapi.createLabel(fapi.toAddr(0xFFF36),"TPUCh3Par3",false); fapi.createWord(fapi.toAddr(0xFFF36));
		fapi.createLabel(fapi.toAddr(0xFFF38),"TPUCh3Par4",false); fapi.createWord(fapi.toAddr(0xFFF38));
		fapi.createLabel(fapi.toAddr(0xFFF3A),"TPUCh3Par5",false); fapi.createWord(fapi.toAddr(0xFFF3A));
		fapi.createLabel(fapi.toAddr(0xFFF3C),"TPUCh3Par6",false); fapi.createWord(fapi.toAddr(0xFFF3C));
		fapi.createLabel(fapi.toAddr(0xFFF3E),"TPUCh3Par7",false); fapi.createWord(fapi.toAddr(0xFFF3E));
		fapi.createLabel(fapi.toAddr(0xFFF40),"TPUCh4Par0",false); fapi.createWord(fapi.toAddr(0xFFF40));
		fapi.createLabel(fapi.toAddr(0xFFF42),"TPUCh4Par1",false); fapi.createWord(fapi.toAddr(0xFFF42));
		fapi.createLabel(fapi.toAddr(0xFFF44),"TPUCh4Par2",false); fapi.createWord(fapi.toAddr(0xFFF44));
		fapi.createLabel(fapi.toAddr(0xFFF46),"TPUCh4Par3",false); fapi.createWord(fapi.toAddr(0xFFF46));
		fapi.createLabel(fapi.toAddr(0xFFF48),"TPUCh4Par4",false); fapi.createWord(fapi.toAddr(0xFFF48));
		fapi.createLabel(fapi.toAddr(0xFFF4A),"TPUCh4Par5",false); fapi.createWord(fapi.toAddr(0xFFF4A));
		fapi.createLabel(fapi.toAddr(0xFFF4C),"TPUCh4Par6",false); fapi.createWord(fapi.toAddr(0xFFF4C));
		fapi.createLabel(fapi.toAddr(0xFFF4E),"TPUCh4Par7",false); fapi.createWord(fapi.toAddr(0xFFF4E));
		fapi.createLabel(fapi.toAddr(0xFFF50),"TPUCh5Par0",false); fapi.createWord(fapi.toAddr(0xFFF50));
		fapi.createLabel(fapi.toAddr(0xFFF52),"TPUCh5Par1",false); fapi.createWord(fapi.toAddr(0xFFF52));
		fapi.createLabel(fapi.toAddr(0xFFF54),"TPUCh5Par2",false); fapi.createWord(fapi.toAddr(0xFFF54));
		fapi.createLabel(fapi.toAddr(0xFFF56),"TPUCh5Par3",false); fapi.createWord(fapi.toAddr(0xFFF56));
		fapi.createLabel(fapi.toAddr(0xFFF58),"TPUCh5Par4",false); fapi.createWord(fapi.toAddr(0xFFF58));
		fapi.createLabel(fapi.toAddr(0xFFF5A),"TPUCh5Par5",false); fapi.createWord(fapi.toAddr(0xFFF5A));
		fapi.createLabel(fapi.toAddr(0xFFF5C),"TPUCh5Par6",false); fapi.createWord(fapi.toAddr(0xFFF5C));
		fapi.createLabel(fapi.toAddr(0xFFF5E),"TPUCh5Par7",false); fapi.createWord(fapi.toAddr(0xFFF5E));
		fapi.createLabel(fapi.toAddr(0xFFF60),"TPUCh6Par0",false); fapi.createWord(fapi.toAddr(0xFFF60));
		fapi.createLabel(fapi.toAddr(0xFFF62),"TPUCh6Par1",false); fapi.createWord(fapi.toAddr(0xFFF62));
		fapi.createLabel(fapi.toAddr(0xFFF64),"TPUCh6Par2",false); fapi.createWord(fapi.toAddr(0xFFF64));
		fapi.createLabel(fapi.toAddr(0xFFF66),"TPUCh6Par3",false); fapi.createWord(fapi.toAddr(0xFFF66));
		fapi.createLabel(fapi.toAddr(0xFFF68),"TPUCh6Par4",false); fapi.createWord(fapi.toAddr(0xFFF68));
		fapi.createLabel(fapi.toAddr(0xFFF6A),"TPUCh6Par5",false); fapi.createWord(fapi.toAddr(0xFFF6A));
		fapi.createLabel(fapi.toAddr(0xFFF6C),"TPUCh6Par6",false); fapi.createWord(fapi.toAddr(0xFFF6C));
		fapi.createLabel(fapi.toAddr(0xFFF6E),"TPUCh6Par7",false); fapi.createWord(fapi.toAddr(0xFFF6E));
		fapi.createLabel(fapi.toAddr(0xFFF70),"TPUCh7Par0",false); fapi.createWord(fapi.toAddr(0xFFF70));
		fapi.createLabel(fapi.toAddr(0xFFF72),"TPUCh7Par1",false); fapi.createWord(fapi.toAddr(0xFFF72));
		fapi.createLabel(fapi.toAddr(0xFFF74),"TPUCh7Par2",false); fapi.createWord(fapi.toAddr(0xFFF74));
		fapi.createLabel(fapi.toAddr(0xFFF76),"TPUCh7Par3",false); fapi.createWord(fapi.toAddr(0xFFF76));
		fapi.createLabel(fapi.toAddr(0xFFF78),"TPUCh7Par4",false); fapi.createWord(fapi.toAddr(0xFFF78));
		fapi.createLabel(fapi.toAddr(0xFFF7A),"TPUCh7Par5",false); fapi.createWord(fapi.toAddr(0xFFF7A));
		fapi.createLabel(fapi.toAddr(0xFFF7C),"TPUCh7Par6",false); fapi.createWord(fapi.toAddr(0xFFF7C));
		fapi.createLabel(fapi.toAddr(0xFFF7E),"TPUCh7Par7",false); fapi.createWord(fapi.toAddr(0xFFF7E));
		fapi.createLabel(fapi.toAddr(0xFFF80),"TPUCh8Par0",false); fapi.createWord(fapi.toAddr(0xFFF80));
		fapi.createLabel(fapi.toAddr(0xFFF82),"TPUCh8Par1",false); fapi.createWord(fapi.toAddr(0xFFF82));
		fapi.createLabel(fapi.toAddr(0xFFF84),"TPUCh8Par2",false); fapi.createWord(fapi.toAddr(0xFFF84));
		fapi.createLabel(fapi.toAddr(0xFFF86),"TPUCh8Par3",false); fapi.createWord(fapi.toAddr(0xFFF86));
		fapi.createLabel(fapi.toAddr(0xFFF88),"TPUCh8Par4",false); fapi.createWord(fapi.toAddr(0xFFF88));
		fapi.createLabel(fapi.toAddr(0xFFF8A),"TPUCh8Par5",false); fapi.createWord(fapi.toAddr(0xFFF8A));
		fapi.createLabel(fapi.toAddr(0xFFF8C),"TPUCh8Par6",false); fapi.createWord(fapi.toAddr(0xFFF8C));
		fapi.createLabel(fapi.toAddr(0xFFF8E),"TPUCh8Par7",false); fapi.createWord(fapi.toAddr(0xFFF8E));
		fapi.createLabel(fapi.toAddr(0xFFF90),"TPUCh9Par0",false); fapi.createWord(fapi.toAddr(0xFFF90));
		fapi.createLabel(fapi.toAddr(0xFFF92),"TPUCh9Par1",false); fapi.createWord(fapi.toAddr(0xFFF92));
		fapi.createLabel(fapi.toAddr(0xFFF94),"TPUCh9Par2",false); fapi.createWord(fapi.toAddr(0xFFF94));
		fapi.createLabel(fapi.toAddr(0xFFF96),"TPUCh9Par3",false); fapi.createWord(fapi.toAddr(0xFFF96));
		fapi.createLabel(fapi.toAddr(0xFFF98),"TPUCh9Par4",false); fapi.createWord(fapi.toAddr(0xFFF98));
		fapi.createLabel(fapi.toAddr(0xFFF9A),"TPUCh9Par5",false); fapi.createWord(fapi.toAddr(0xFFF9A));
		fapi.createLabel(fapi.toAddr(0xFFF9C),"TPUCh9Par6",false); fapi.createWord(fapi.toAddr(0xFFF9C));
		fapi.createLabel(fapi.toAddr(0xFFF9E),"TPUCh9Par7",false); fapi.createWord(fapi.toAddr(0xFFF9E));
		fapi.createLabel(fapi.toAddr(0xFFFA0),"TPUCh10Par0",false); fapi.createWord(fapi.toAddr(0xFFFA0));
		fapi.createLabel(fapi.toAddr(0xFFFA2),"TPUCh10Par1",false); fapi.createWord(fapi.toAddr(0xFFFA2));
		fapi.createLabel(fapi.toAddr(0xFFFA4),"TPUCh10Par2",false); fapi.createWord(fapi.toAddr(0xFFFA4));
		fapi.createLabel(fapi.toAddr(0xFFFA6),"TPUCh10Par3",false); fapi.createWord(fapi.toAddr(0xFFFA6));
		fapi.createLabel(fapi.toAddr(0xFFFA8),"TPUCh10Par4",false); fapi.createWord(fapi.toAddr(0xFFFA8));
		fapi.createLabel(fapi.toAddr(0xFFFAA),"TPUCh10Par5",false); fapi.createWord(fapi.toAddr(0xFFFAA));
		fapi.createLabel(fapi.toAddr(0xFFFAC),"TPUCh10Par6",false); fapi.createWord(fapi.toAddr(0xFFFAC));
		fapi.createLabel(fapi.toAddr(0xFFFAE),"TPUCh10Par7",false); fapi.createWord(fapi.toAddr(0xFFFAE));
		fapi.createLabel(fapi.toAddr(0xFFFB0),"TPUCh11Par0",false); fapi.createWord(fapi.toAddr(0xFFFB0));
		fapi.createLabel(fapi.toAddr(0xFFFB2),"TPUCh11Par1",false); fapi.createWord(fapi.toAddr(0xFFFB2));
		fapi.createLabel(fapi.toAddr(0xFFFB4),"TPUCh11Par2",false); fapi.createWord(fapi.toAddr(0xFFFB4));
		fapi.createLabel(fapi.toAddr(0xFFFB6),"TPUCh11Par3",false); fapi.createWord(fapi.toAddr(0xFFFB6));
		fapi.createLabel(fapi.toAddr(0xFFFB8),"TPUCh11Par4",false); fapi.createWord(fapi.toAddr(0xFFFB8));
		fapi.createLabel(fapi.toAddr(0xFFFBA),"TPUCh11Par5",false); fapi.createWord(fapi.toAddr(0xFFFBA));
		fapi.createLabel(fapi.toAddr(0xFFFBC),"TPUCh11Par6",false); fapi.createWord(fapi.toAddr(0xFFFBC));
		fapi.createLabel(fapi.toAddr(0xFFFBE),"TPUCh11Par7",false); fapi.createWord(fapi.toAddr(0xFFFBE));
		fapi.createLabel(fapi.toAddr(0xFFFC0),"TPUCh12Par0",false); fapi.createWord(fapi.toAddr(0xFFFC0));
		fapi.createLabel(fapi.toAddr(0xFFFC2),"TPUCh12Par1",false); fapi.createWord(fapi.toAddr(0xFFFC2));
		fapi.createLabel(fapi.toAddr(0xFFFC4),"TPUCh12Par2",false); fapi.createWord(fapi.toAddr(0xFFFC4));
		fapi.createLabel(fapi.toAddr(0xFFFC6),"TPUCh12Par3",false); fapi.createWord(fapi.toAddr(0xFFFC6));
		fapi.createLabel(fapi.toAddr(0xFFFC8),"TPUCh12Par4",false); fapi.createWord(fapi.toAddr(0xFFFC8));
		fapi.createLabel(fapi.toAddr(0xFFFCA),"TPUCh12Par5",false); fapi.createWord(fapi.toAddr(0xFFFCA));
		fapi.createLabel(fapi.toAddr(0xFFFCC),"TPUCh12Par6",false); fapi.createWord(fapi.toAddr(0xFFFCC));
		fapi.createLabel(fapi.toAddr(0xFFFCE),"TPUCh12Par7",false); fapi.createWord(fapi.toAddr(0xFFFCE));
		fapi.createLabel(fapi.toAddr(0xFFFD0),"TPUCh13Par0",false); fapi.createWord(fapi.toAddr(0xFFFD0));
		fapi.createLabel(fapi.toAddr(0xFFFD2),"TPUCh13Par1",false); fapi.createWord(fapi.toAddr(0xFFFD2));
		fapi.createLabel(fapi.toAddr(0xFFFD4),"TPUCh13Par2",false); fapi.createWord(fapi.toAddr(0xFFFD4));
		fapi.createLabel(fapi.toAddr(0xFFFD6),"TPUCh13Par3",false); fapi.createWord(fapi.toAddr(0xFFFD6));
		fapi.createLabel(fapi.toAddr(0xFFFD8),"TPUCh13Par4",false); fapi.createWord(fapi.toAddr(0xFFFD8));
		fapi.createLabel(fapi.toAddr(0xFFFDA),"TPUCh13Par5",false); fapi.createWord(fapi.toAddr(0xFFFDA));
		fapi.createLabel(fapi.toAddr(0xFFFDC),"TPUCh13Par6",false); fapi.createWord(fapi.toAddr(0xFFFDC));
		fapi.createLabel(fapi.toAddr(0xFFFDE),"TPUCh13Par7",false); fapi.createWord(fapi.toAddr(0xFFFDE));
		fapi.createLabel(fapi.toAddr(0xFFFE0),"TPUCh14Par0",false); fapi.createWord(fapi.toAddr(0xFFFE0));
		fapi.createLabel(fapi.toAddr(0xFFFE2),"TPUCh14Par1",false); fapi.createWord(fapi.toAddr(0xFFFE2));
		fapi.createLabel(fapi.toAddr(0xFFFE4),"TPUCh14Par2",false); fapi.createWord(fapi.toAddr(0xFFFE4));
		fapi.createLabel(fapi.toAddr(0xFFFE6),"TPUCh14Par3",false); fapi.createWord(fapi.toAddr(0xFFFE6));
		fapi.createLabel(fapi.toAddr(0xFFFE8),"TPUCh14Par4",false); fapi.createWord(fapi.toAddr(0xFFFE8));
		fapi.createLabel(fapi.toAddr(0xFFFEA),"TPUCh14Par5",false); fapi.createWord(fapi.toAddr(0xFFFEA));
		fapi.createLabel(fapi.toAddr(0xFFFEC),"TPUCh14Par6",false); fapi.createWord(fapi.toAddr(0xFFFEC));
		fapi.createLabel(fapi.toAddr(0xFFFEE),"TPUCh14Par7",false); fapi.createWord(fapi.toAddr(0xFFFEE));
		fapi.createLabel(fapi.toAddr(0xFFFF0),"TPUCh15Par0",false); fapi.createWord(fapi.toAddr(0xFFFF0));
		fapi.createLabel(fapi.toAddr(0xFFFF2),"TPUCh15Par1",false); fapi.createWord(fapi.toAddr(0xFFFF2));
		fapi.createLabel(fapi.toAddr(0xFFFF4),"TPUCh15Par2",false); fapi.createWord(fapi.toAddr(0xFFFF4));
		fapi.createLabel(fapi.toAddr(0xFFFF6),"TPUCh15Par3",false); fapi.createWord(fapi.toAddr(0xFFFF6));
		fapi.createLabel(fapi.toAddr(0xFFFF8),"TPUCh15Par4",false); fapi.createWord(fapi.toAddr(0xFFFF8));
		fapi.createLabel(fapi.toAddr(0xFFFFA),"TPUCh15Par5",false); fapi.createWord(fapi.toAddr(0xFFFFA));
		fapi.createLabel(fapi.toAddr(0xFFFFC),"TPUCh15Par6",false); fapi.createWord(fapi.toAddr(0xFFFFC));
		fapi.createLabel(fapi.toAddr(0xFFFFE),"TPUCh15Par7",false); fapi.createWord(fapi.toAddr(0xFFFFE));
	}

	private void AN82527Labels(FlatProgramAPI fapi) throws Exception
	{
		fapi.createLabel(fapi.toAddr(0x80000),"AN82527_Control",false); fapi.createLabel(fapi.toAddr(0xB03CE),"Mirrored_AN82527_Control",false); 
		fapi.createLabel(fapi.toAddr(0x80001),"AN82527_Status",false); fapi.createLabel(fapi.toAddr(0xB03CF),"Mirrored_AN82527_Status",false); 
		fapi.createLabel(fapi.toAddr(0x80002),"AN82527_CPU_Interface",false); fapi.createLabel(fapi.toAddr(0xB03D0),"Mirrored_AN82527_CPU_Interface",false); 
		fapi.createLabel(fapi.toAddr(0x80003),"AN82527_Reserved",false); fapi.createLabel(fapi.toAddr(0xB03D1),"Mirrored_AN82527_Reserved",false); 
		fapi.createLabel(fapi.toAddr(0x80004),"AN82527_High_Speed_Read_Low_Byte",false); fapi.createLabel(fapi.toAddr(0xB03D2),"Mirrored_AN82527_High_Speed_Read_Low_Byte",false); 
		fapi.createLabel(fapi.toAddr(0x80005),"AN82527_High_Speed_Read_High_Byte",false); fapi.createLabel(fapi.toAddr(0xB03D3),"Mirrored_AN82527_High_Speed_Read_High_Byte",false); 
		fapi.createLabel(fapi.toAddr(0x80006),"AN82527_Global_Mask–Standard_A",false); fapi.createLabel(fapi.toAddr(0xB03D4),"Mirrored_AN82527_Global_Mask–Standard_A",false); 
		fapi.createLabel(fapi.toAddr(0x80007),"AN82527_Global_Mask–Standard_B",false); fapi.createLabel(fapi.toAddr(0xB03D5),"Mirrored_AN82527_Global_Mask–Standard_B",false); 
		fapi.createLabel(fapi.toAddr(0x80008),"AN82527_Global_Mask–Extended_A",false); fapi.createLabel(fapi.toAddr(0xB03D6),"Mirrored_AN82527_Global_Mask–Extended_A",false); 
		fapi.createLabel(fapi.toAddr(0x80009),"AN82527_Global_Mask–Extended_B",false); fapi.createLabel(fapi.toAddr(0xB03D7),"Mirrored_AN82527_Global_Mask–Extended_B",false); 
		fapi.createLabel(fapi.toAddr(0x8000A),"AN82527_Global_Mask–Extended_C",false); fapi.createLabel(fapi.toAddr(0xB03D8),"Mirrored_AN82527_Global_Mask–Extended_C",false); 
		fapi.createLabel(fapi.toAddr(0x8000B),"AN82527_Global_Mask–Extended_D",false); fapi.createLabel(fapi.toAddr(0xB03D9),"Mirrored_AN82527_Global_Mask–Extended_D",false); 
		fapi.createLabel(fapi.toAddr(0x8000C),"AN82527_Message15MaskA",false); fapi.createLabel(fapi.toAddr(0xB03DA),"Mirrored_AN82527_Message15MaskA",false); 
		fapi.createLabel(fapi.toAddr(0x8000D),"AN82527_Message15MaskB",false); fapi.createLabel(fapi.toAddr(0xB03DB),"Mirrored_AN82527_Message15MaskB",false); 
		fapi.createLabel(fapi.toAddr(0x8000E),"AN82527_Message15MaskC",false); fapi.createLabel(fapi.toAddr(0xB03DC),"Mirrored_AN82527_Message15MaskC",false); 
		fapi.createLabel(fapi.toAddr(0x8000F),"AN82527_Message15MaskD",false); fapi.createLabel(fapi.toAddr(0xB03DD),"Mirrored_AN82527_Message15MaskD",false); 
		fapi.createLabel(fapi.toAddr(0x80010),"AN82527_Message1-Control0",false); fapi.createLabel(fapi.toAddr(0xB03DE),"Mirrored_AN82527_Message1-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80011),"AN82527_Message1-Control1",false); fapi.createLabel(fapi.toAddr(0xB03DF),"Mirrored_AN82527_Message1-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80012),"AN82527_Message1-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB03E0),"Mirrored_AN82527_Message1-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80013),"AN82527_Message1-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB03E1),"Mirrored_AN82527_Message1-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80014),"AN82527_Message1-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB03E2),"Mirrored_AN82527_Message1-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80015),"AN82527_Message1-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB03E3),"Mirrored_AN82527_Message1-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80016),"AN82527_Message1-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB03E4),"Mirrored_AN82527_Message1-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80017),"AN82527_Message1-Data0",false); fapi.createLabel(fapi.toAddr(0xB03E5),"Mirrored_AN82527_Message1-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80018),"AN82527_Message1-Data1",false); fapi.createLabel(fapi.toAddr(0xB03E6),"Mirrored_AN82527_Message1-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80019),"AN82527_Message1-Data2",false); fapi.createLabel(fapi.toAddr(0xB03E7),"Mirrored_AN82527_Message1-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8001A),"AN82527_Message1-Data3",false); fapi.createLabel(fapi.toAddr(0xB03E8),"Mirrored_AN82527_Message1-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8001B),"AN82527_Message1-Data4",false); fapi.createLabel(fapi.toAddr(0xB03E9),"Mirrored_AN82527_Message1-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8001C),"AN82527_Message1-Data5",false); fapi.createLabel(fapi.toAddr(0xB03EA),"Mirrored_AN82527_Message1-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8001D),"AN82527_Message1-Data6",false); fapi.createLabel(fapi.toAddr(0xB03EB),"Mirrored_AN82527_Message1-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8001E),"AN82527_Message1-Data7",false); fapi.createLabel(fapi.toAddr(0xB03EC),"Mirrored_AN82527_Message1-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8001F),"AN82527_CLKOUT",false); fapi.createLabel(fapi.toAddr(0xB03ED),"Mirrored_AN82527_CLKOUT",false); 
		fapi.createLabel(fapi.toAddr(0x80020),"AN82527_Message2-Control0",false); fapi.createLabel(fapi.toAddr(0xB03EE),"Mirrored_AN82527_Message2-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80021),"AN82527_Message2-Control1",false); fapi.createLabel(fapi.toAddr(0xB03EF),"Mirrored_AN82527_Message2-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80022),"AN82527_Message2-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB03F0),"Mirrored_AN82527_Message2-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80023),"AN82527_Message2-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB03F1),"Mirrored_AN82527_Message2-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80024),"AN82527_Message2-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB03F2),"Mirrored_AN82527_Message2-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80025),"AN82527_Message2-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB03F3),"Mirrored_AN82527_Message2-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80026),"AN82527_Message2-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB03F4),"Mirrored_AN82527_Message2-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80027),"AN82527_Message2-Data0",false); fapi.createLabel(fapi.toAddr(0xB03F5),"Mirrored_AN82527_Message2-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80028),"AN82527_Message2-Data1",false); fapi.createLabel(fapi.toAddr(0xB03F6),"Mirrored_AN82527_Message2-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80029),"AN82527_Message2-Data2",false); fapi.createLabel(fapi.toAddr(0xB03F7),"Mirrored_AN82527_Message2-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8002A),"AN82527_Message2-Data3",false); fapi.createLabel(fapi.toAddr(0xB03F8),"Mirrored_AN82527_Message2-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8002B),"AN82527_Message2-Data4",false); fapi.createLabel(fapi.toAddr(0xB03F9),"Mirrored_AN82527_Message2-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8002C),"AN82527_Message2-Data5",false); fapi.createLabel(fapi.toAddr(0xB03FA),"Mirrored_AN82527_Message2-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8002D),"AN82527_Message2-Data6",false); fapi.createLabel(fapi.toAddr(0xB03FB),"Mirrored_AN82527_Message2-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8002E),"AN82527_Message2-Data7",false); fapi.createLabel(fapi.toAddr(0xB03FC),"Mirrored_AN82527_Message2-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8002F),"AN82527_Bus_Configuration",false); fapi.createLabel(fapi.toAddr(0xB03FD),"Mirrored_AN82527_Bus_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80030),"AN82527_Message3-Control0",false); fapi.createLabel(fapi.toAddr(0xB03FE),"Mirrored_AN82527_Message3-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80031),"AN82527_Message3-Control1",false); fapi.createLabel(fapi.toAddr(0xB03FF),"Mirrored_AN82527_Message3-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80032),"AN82527_Message3-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0400),"Mirrored_AN82527_Message3-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80033),"AN82527_Message3-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0401),"Mirrored_AN82527_Message3-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80034),"AN82527_Message3-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0402),"Mirrored_AN82527_Message3-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80035),"AN82527_Message3-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0403),"Mirrored_AN82527_Message3-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80036),"AN82527_Message3-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0404),"Mirrored_AN82527_Message3-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80037),"AN82527_Message3-Data0",false); fapi.createLabel(fapi.toAddr(0xB0405),"Mirrored_AN82527_Message3-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80038),"AN82527_Message3-Data1",false); fapi.createLabel(fapi.toAddr(0xB0406),"Mirrored_AN82527_Message3-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80039),"AN82527_Message3-Data2",false); fapi.createLabel(fapi.toAddr(0xB0407),"Mirrored_AN82527_Message3-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8003A),"AN82527_Message3-Data3",false); fapi.createLabel(fapi.toAddr(0xB0408),"Mirrored_AN82527_Message3-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8003B),"AN82527_Message3-Data4",false); fapi.createLabel(fapi.toAddr(0xB0409),"Mirrored_AN82527_Message3-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8003C),"AN82527_Message3-Data5",false); fapi.createLabel(fapi.toAddr(0xB040A),"Mirrored_AN82527_Message3-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8003D),"AN82527_Message3-Data6",false); fapi.createLabel(fapi.toAddr(0xB040B),"Mirrored_AN82527_Message3-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8003E),"AN82527_Message3-Data7",false); fapi.createLabel(fapi.toAddr(0xB040C),"Mirrored_AN82527_Message3-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8003F),"AN82527_Bit_Timing0",false); fapi.createLabel(fapi.toAddr(0xB040D),"Mirrored_AN82527_Bit_Timing0",false); 
		fapi.createLabel(fapi.toAddr(0x80040),"AN82527_Message4-Control0",false); fapi.createLabel(fapi.toAddr(0xB040E),"Mirrored_AN82527_Message4-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80041),"AN82527_Message4-Control1",false); fapi.createLabel(fapi.toAddr(0xB040F),"Mirrored_AN82527_Message4-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80042),"AN82527_Message4-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0410),"Mirrored_AN82527_Message4-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80043),"AN82527_Message4-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0411),"Mirrored_AN82527_Message4-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80044),"AN82527_Message4-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0412),"Mirrored_AN82527_Message4-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80045),"AN82527_Message4-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0413),"Mirrored_AN82527_Message4-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80046),"AN82527_Message4-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0414),"Mirrored_AN82527_Message4-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80047),"AN82527_Message4-Data0",false); fapi.createLabel(fapi.toAddr(0xB0415),"Mirrored_AN82527_Message4-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80048),"AN82527_Message4-Data1",false); fapi.createLabel(fapi.toAddr(0xB0416),"Mirrored_AN82527_Message4-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80049),"AN82527_Message4-Data2",false); fapi.createLabel(fapi.toAddr(0xB0417),"Mirrored_AN82527_Message4-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8004A),"AN82527_Message4-Data3",false); fapi.createLabel(fapi.toAddr(0xB0418),"Mirrored_AN82527_Message4-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8004B),"AN82527_Message4-Data4",false); fapi.createLabel(fapi.toAddr(0xB0419),"Mirrored_AN82527_Message4-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8004C),"AN82527_Message4-Data5",false); fapi.createLabel(fapi.toAddr(0xB041A),"Mirrored_AN82527_Message4-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8004D),"AN82527_Message4-Data6",false); fapi.createLabel(fapi.toAddr(0xB041B),"Mirrored_AN82527_Message4-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8004E),"AN82527_Message4-Data7",false); fapi.createLabel(fapi.toAddr(0xB041C),"Mirrored_AN82527_Message4-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8004F),"AN82527_Bit_Timing1",false); fapi.createLabel(fapi.toAddr(0xB041D),"Mirrored_AN82527_Bit_Timing1",false); 
		fapi.createLabel(fapi.toAddr(0x80050),"AN82527_Message5-Control0",false); fapi.createLabel(fapi.toAddr(0xB041E),"Mirrored_AN82527_Message5-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80051),"AN82527_Message5-Control1",false); fapi.createLabel(fapi.toAddr(0xB041F),"Mirrored_AN82527_Message5-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80052),"AN82527_Message5-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0420),"Mirrored_AN82527_Message5-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80053),"AN82527_Message5-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0421),"Mirrored_AN82527_Message5-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80054),"AN82527_Message5-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0422),"Mirrored_AN82527_Message5-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80055),"AN82527_Message5-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0423),"Mirrored_AN82527_Message5-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80056),"AN82527_Message5-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0424),"Mirrored_AN82527_Message5-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80057),"AN82527_Message5-Data0",false); fapi.createLabel(fapi.toAddr(0xB0425),"Mirrored_AN82527_Message5-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80058),"AN82527_Message5-Data1",false); fapi.createLabel(fapi.toAddr(0xB0426),"Mirrored_AN82527_Message5-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80059),"AN82527_Message5-Data2",false); fapi.createLabel(fapi.toAddr(0xB0427),"Mirrored_AN82527_Message5-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8005A),"AN82527_Message5-Data3",false); fapi.createLabel(fapi.toAddr(0xB0428),"Mirrored_AN82527_Message5-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8005B),"AN82527_Message5-Data4",false); fapi.createLabel(fapi.toAddr(0xB0429),"Mirrored_AN82527_Message5-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8005C),"AN82527_Message5-Data5",false); fapi.createLabel(fapi.toAddr(0xB042A),"Mirrored_AN82527_Message5-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8005D),"AN82527_Message5-Data6",false); fapi.createLabel(fapi.toAddr(0xB042B),"Mirrored_AN82527_Message5-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8005E),"AN82527_Message5-Data7",false); fapi.createLabel(fapi.toAddr(0xB042C),"Mirrored_AN82527_Message5-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8005F),"AN82527_Interrupt",false); fapi.createLabel(fapi.toAddr(0xB042D),"Mirrored_AN82527_Interrupt",false); 
		fapi.createLabel(fapi.toAddr(0x80060),"AN82527_Message6-Control0",false); fapi.createLabel(fapi.toAddr(0xB042E),"Mirrored_AN82527_Message6-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80061),"AN82527_Message6-Control1",false); fapi.createLabel(fapi.toAddr(0xB042F),"Mirrored_AN82527_Message6-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80062),"AN82527_Message6-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0430),"Mirrored_AN82527_Message6-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80063),"AN82527_Message6-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0431),"Mirrored_AN82527_Message6-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80064),"AN82527_Message6-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0432),"Mirrored_AN82527_Message6-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80065),"AN82527_Message6-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0433),"Mirrored_AN82527_Message6-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80066),"AN82527_Message6-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0434),"Mirrored_AN82527_Message6-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80067),"AN82527_Message6-Data0",false); fapi.createLabel(fapi.toAddr(0xB0435),"Mirrored_AN82527_Message6-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80068),"AN82527_Message6-Data1",false); fapi.createLabel(fapi.toAddr(0xB0436),"Mirrored_AN82527_Message6-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80069),"AN82527_Message6-Data2",false); fapi.createLabel(fapi.toAddr(0xB0437),"Mirrored_AN82527_Message6-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8006A),"AN82527_Message6-Data3",false); fapi.createLabel(fapi.toAddr(0xB0438),"Mirrored_AN82527_Message6-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8006B),"AN82527_Message6-Data4",false); fapi.createLabel(fapi.toAddr(0xB0439),"Mirrored_AN82527_Message6-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8006C),"AN82527_Message6-Data5",false); fapi.createLabel(fapi.toAddr(0xB043A),"Mirrored_AN82527_Message6-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8006D),"AN82527_Message6-Data6",false); fapi.createLabel(fapi.toAddr(0xB043B),"Mirrored_AN82527_Message6-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8006E),"AN82527_Message6-Data7",false); fapi.createLabel(fapi.toAddr(0xB043C),"Mirrored_AN82527_Message6-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8006F),"AN82527_Reserved",false); fapi.createLabel(fapi.toAddr(0xB043D),"Mirrored_AN82527_Reserved",false); 
		fapi.createLabel(fapi.toAddr(0x80070),"AN82527_Message7-Control0",false); fapi.createLabel(fapi.toAddr(0xB043E),"Mirrored_AN82527_Message7-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80071),"AN82527_Message7-Control1",false); fapi.createLabel(fapi.toAddr(0xB043F),"Mirrored_AN82527_Message7-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80072),"AN82527_Message7-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0440),"Mirrored_AN82527_Message7-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80073),"AN82527_Message7-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0441),"Mirrored_AN82527_Message7-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80074),"AN82527_Message7-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0442),"Mirrored_AN82527_Message7-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80075),"AN82527_Message7-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0443),"Mirrored_AN82527_Message7-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80076),"AN82527_Message7-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0444),"Mirrored_AN82527_Message7-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80077),"AN82527_Message7-Data0",false); fapi.createLabel(fapi.toAddr(0xB0445),"Mirrored_AN82527_Message7-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80078),"AN82527_Message7-Data1",false); fapi.createLabel(fapi.toAddr(0xB0446),"Mirrored_AN82527_Message7-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80079),"AN82527_Message7-Data2",false); fapi.createLabel(fapi.toAddr(0xB0447),"Mirrored_AN82527_Message7-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8007A),"AN82527_Message7-Data3",false); fapi.createLabel(fapi.toAddr(0xB0448),"Mirrored_AN82527_Message7-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8007B),"AN82527_Message7-Data4",false); fapi.createLabel(fapi.toAddr(0xB0449),"Mirrored_AN82527_Message7-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8007C),"AN82527_Message7-Data5",false); fapi.createLabel(fapi.toAddr(0xB044A),"Mirrored_AN82527_Message7-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8007D),"AN82527_Message7-Data6",false); fapi.createLabel(fapi.toAddr(0xB044B),"Mirrored_AN82527_Message7-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8007E),"AN82527_Message7-Data7",false); fapi.createLabel(fapi.toAddr(0xB044C),"Mirrored_AN82527_Message7-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8007F),"AN82527_Reserved",false); fapi.createLabel(fapi.toAddr(0xB044D),"Mirrored_AN82527_Reserved",false); 
		fapi.createLabel(fapi.toAddr(0x80080),"AN82527_Message8-Control0",false); fapi.createLabel(fapi.toAddr(0xB044E),"Mirrored_AN82527_Message8-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80081),"AN82527_Message8-Control1",false); fapi.createLabel(fapi.toAddr(0xB044F),"Mirrored_AN82527_Message8-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80082),"AN82527_Message8-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0450),"Mirrored_AN82527_Message8-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80083),"AN82527_Message8-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0451),"Mirrored_AN82527_Message8-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80084),"AN82527_Message8-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0452),"Mirrored_AN82527_Message8-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80085),"AN82527_Message8-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0453),"Mirrored_AN82527_Message8-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80086),"AN82527_Message8-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0454),"Mirrored_AN82527_Message8-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80087),"AN82527_Message8-Data0",false); fapi.createLabel(fapi.toAddr(0xB0455),"Mirrored_AN82527_Message8-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80088),"AN82527_Message8-Data1",false); fapi.createLabel(fapi.toAddr(0xB0456),"Mirrored_AN82527_Message8-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80089),"AN82527_Message8-Data2",false); fapi.createLabel(fapi.toAddr(0xB0457),"Mirrored_AN82527_Message8-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8008A),"AN82527_Message8-Data3",false); fapi.createLabel(fapi.toAddr(0xB0458),"Mirrored_AN82527_Message8-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8008B),"AN82527_Message8-Data4",false); fapi.createLabel(fapi.toAddr(0xB0459),"Mirrored_AN82527_Message8-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8008C),"AN82527_Message8-Data5",false); fapi.createLabel(fapi.toAddr(0xB045A),"Mirrored_AN82527_Message8-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8008D),"AN82527_Message8-Data6",false); fapi.createLabel(fapi.toAddr(0xB045B),"Mirrored_AN82527_Message8-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8008E),"AN82527_Message8-Data7",false); fapi.createLabel(fapi.toAddr(0xB045C),"Mirrored_AN82527_Message8-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8008F),"AN82527_Reserved",false); fapi.createLabel(fapi.toAddr(0xB045D),"Mirrored_AN82527_Reserved",false); 
		fapi.createLabel(fapi.toAddr(0x80090),"AN82527_Message9-Control0",false); fapi.createLabel(fapi.toAddr(0xB045E),"Mirrored_AN82527_Message9-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x80091),"AN82527_Message9-Control1",false); fapi.createLabel(fapi.toAddr(0xB045F),"Mirrored_AN82527_Message9-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x80092),"AN82527_Message9-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0460),"Mirrored_AN82527_Message9-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x80093),"AN82527_Message9-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0461),"Mirrored_AN82527_Message9-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x80094),"AN82527_Message9-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0462),"Mirrored_AN82527_Message9-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x80095),"AN82527_Message9-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0463),"Mirrored_AN82527_Message9-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x80096),"AN82527_Message9-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0464),"Mirrored_AN82527_Message9-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x80097),"AN82527_Message9-Data0",false); fapi.createLabel(fapi.toAddr(0xB0465),"Mirrored_AN82527_Message9-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x80098),"AN82527_Message9-Data1",false); fapi.createLabel(fapi.toAddr(0xB0466),"Mirrored_AN82527_Message9-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x80099),"AN82527_Message9-Data2",false); fapi.createLabel(fapi.toAddr(0xB0467),"Mirrored_AN82527_Message9-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x8009A),"AN82527_Message9-Data3",false); fapi.createLabel(fapi.toAddr(0xB0468),"Mirrored_AN82527_Message9-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x8009B),"AN82527_Message9-Data4",false); fapi.createLabel(fapi.toAddr(0xB0469),"Mirrored_AN82527_Message9-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x8009C),"AN82527_Message9-Data5",false); fapi.createLabel(fapi.toAddr(0xB046A),"Mirrored_AN82527_Message9-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x8009D),"AN82527_Message9-Data6",false); fapi.createLabel(fapi.toAddr(0xB046B),"Mirrored_AN82527_Message9-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x8009E),"AN82527_Message9-Data7",false); fapi.createLabel(fapi.toAddr(0xB046C),"Mirrored_AN82527_Message9-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x8009F),"AN82527_Port1_Configuration",false); fapi.createLabel(fapi.toAddr(0xB046D),"Mirrored_AN82527_Port1_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800A0),"AN82527_Message10-Control0",false); fapi.createLabel(fapi.toAddr(0xB046E),"Mirrored_AN82527_Message10-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x800A1),"AN82527_Message10-Control1",false); fapi.createLabel(fapi.toAddr(0xB046F),"Mirrored_AN82527_Message10-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x800A2),"AN82527_Message10-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0470),"Mirrored_AN82527_Message10-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x800A3),"AN82527_Message10-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0471),"Mirrored_AN82527_Message10-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x800A4),"AN82527_Message10-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0472),"Mirrored_AN82527_Message10-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x800A5),"AN82527_Message10-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0473),"Mirrored_AN82527_Message10-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x800A6),"AN82527_Message10-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0474),"Mirrored_AN82527_Message10-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800A7),"AN82527_Message10-Data0",false); fapi.createLabel(fapi.toAddr(0xB0475),"Mirrored_AN82527_Message10-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x800A8),"AN82527_Message10-Data1",false); fapi.createLabel(fapi.toAddr(0xB0476),"Mirrored_AN82527_Message10-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x800A9),"AN82527_Message10-Data2",false); fapi.createLabel(fapi.toAddr(0xB0477),"Mirrored_AN82527_Message10-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x800AA),"AN82527_Message10-Data3",false); fapi.createLabel(fapi.toAddr(0xB0478),"Mirrored_AN82527_Message10-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x800AB),"AN82527_Message10-Data4",false); fapi.createLabel(fapi.toAddr(0xB0479),"Mirrored_AN82527_Message10-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x800AC),"AN82527_Message10-Data5",false); fapi.createLabel(fapi.toAddr(0xB047A),"Mirrored_AN82527_Message10-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x800AD),"AN82527_Message10-Data6",false); fapi.createLabel(fapi.toAddr(0xB047B),"Mirrored_AN82527_Message10-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x800AE),"AN82527_Message10-Data7",false); fapi.createLabel(fapi.toAddr(0xB047C),"Mirrored_AN82527_Message10-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x800AF),"AN82527_Port2_Configuration",false); fapi.createLabel(fapi.toAddr(0xB047D),"Mirrored_AN82527_Port2_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800B0),"AN82527_Message11-Control0",false); fapi.createLabel(fapi.toAddr(0xB047E),"Mirrored_AN82527_Message11-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x800B1),"AN82527_Message11-Control1",false); fapi.createLabel(fapi.toAddr(0xB047F),"Mirrored_AN82527_Message11-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x800B2),"AN82527_Message11-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0480),"Mirrored_AN82527_Message11-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x800B3),"AN82527_Message11-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0481),"Mirrored_AN82527_Message11-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x800B4),"AN82527_Message11-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0482),"Mirrored_AN82527_Message11-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x800B5),"AN82527_Message11-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0483),"Mirrored_AN82527_Message11-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x800B6),"AN82527_Message11-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0484),"Mirrored_AN82527_Message11-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800B7),"AN82527_Message11-Data0",false); fapi.createLabel(fapi.toAddr(0xB0485),"Mirrored_AN82527_Message11-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x800B8),"AN82527_Message11-Data1",false); fapi.createLabel(fapi.toAddr(0xB0486),"Mirrored_AN82527_Message11-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x800B9),"AN82527_Message11-Data2",false); fapi.createLabel(fapi.toAddr(0xB0487),"Mirrored_AN82527_Message11-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x800BA),"AN82527_Message11-Data3",false); fapi.createLabel(fapi.toAddr(0xB0488),"Mirrored_AN82527_Message11-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x800BB),"AN82527_Message11-Data4",false); fapi.createLabel(fapi.toAddr(0xB0489),"Mirrored_AN82527_Message11-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x800BC),"AN82527_Message11-Data5",false); fapi.createLabel(fapi.toAddr(0xB048A),"Mirrored_AN82527_Message11-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x800BD),"AN82527_Message11-Data6",false); fapi.createLabel(fapi.toAddr(0xB048B),"Mirrored_AN82527_Message11-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x800BE),"AN82527_Message11-Data7",false); fapi.createLabel(fapi.toAddr(0xB048C),"Mirrored_AN82527_Message11-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x800BF),"AN82527_Port1_In",false); fapi.createLabel(fapi.toAddr(0xB048D),"Mirrored_AN82527_Port1_In",false); 
		fapi.createLabel(fapi.toAddr(0x800C0),"AN82527_Message12-Control0",false); fapi.createLabel(fapi.toAddr(0xB048E),"Mirrored_AN82527_Message12-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x800C1),"AN82527_Message12-Control1",false); fapi.createLabel(fapi.toAddr(0xB048F),"Mirrored_AN82527_Message12-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x800C2),"AN82527_Message12-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB0490),"Mirrored_AN82527_Message12-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x800C3),"AN82527_Message12-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB0491),"Mirrored_AN82527_Message12-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x800C4),"AN82527_Message12-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB0492),"Mirrored_AN82527_Message12-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x800C5),"AN82527_Message12-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB0493),"Mirrored_AN82527_Message12-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x800C6),"AN82527_Message12-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB0494),"Mirrored_AN82527_Message12-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800C7),"AN82527_Message12-Data0",false); fapi.createLabel(fapi.toAddr(0xB0495),"Mirrored_AN82527_Message12-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x800C8),"AN82527_Message12-Data1",false); fapi.createLabel(fapi.toAddr(0xB0496),"Mirrored_AN82527_Message12-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x800C9),"AN82527_Message12-Data2",false); fapi.createLabel(fapi.toAddr(0xB0497),"Mirrored_AN82527_Message12-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x800CA),"AN82527_Message12-Data3",false); fapi.createLabel(fapi.toAddr(0xB0498),"Mirrored_AN82527_Message12-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x800CB),"AN82527_Message12-Data4",false); fapi.createLabel(fapi.toAddr(0xB0499),"Mirrored_AN82527_Message12-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x800CC),"AN82527_Message12-Data5",false); fapi.createLabel(fapi.toAddr(0xB049A),"Mirrored_AN82527_Message12-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x800CD),"AN82527_Message12-Data6",false); fapi.createLabel(fapi.toAddr(0xB049B),"Mirrored_AN82527_Message12-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x800CE),"AN82527_Message12-Data7",false); fapi.createLabel(fapi.toAddr(0xB049C),"Mirrored_AN82527_Message12-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x800CF),"AN82527_Port2_In",false); fapi.createLabel(fapi.toAddr(0xB049D),"Mirrored_AN82527_Port2_In",false); 
		fapi.createLabel(fapi.toAddr(0x800D0),"AN82527_Message13-Control0",false); fapi.createLabel(fapi.toAddr(0xB049E),"Mirrored_AN82527_Message13-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x800D1),"AN82527_Message13-Control1",false); fapi.createLabel(fapi.toAddr(0xB049F),"Mirrored_AN82527_Message13-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x800D2),"AN82527_Message13-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB04A0),"Mirrored_AN82527_Message13-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x800D3),"AN82527_Message13-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB04A1),"Mirrored_AN82527_Message13-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x800D4),"AN82527_Message13-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB04A2),"Mirrored_AN82527_Message13-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x800D5),"AN82527_Message13-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB04A3),"Mirrored_AN82527_Message13-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x800D6),"AN82527_Message13-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB04A4),"Mirrored_AN82527_Message13-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800D7),"AN82527_Message13-Data0",false); fapi.createLabel(fapi.toAddr(0xB04A5),"Mirrored_AN82527_Message13-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x800D8),"AN82527_Message13-Data1",false); fapi.createLabel(fapi.toAddr(0xB04A6),"Mirrored_AN82527_Message13-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x800D9),"AN82527_Message13-Data2",false); fapi.createLabel(fapi.toAddr(0xB04A7),"Mirrored_AN82527_Message13-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x800DA),"AN82527_Message13-Data3",false); fapi.createLabel(fapi.toAddr(0xB04A8),"Mirrored_AN82527_Message13-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x800DB),"AN82527_Message13-Data4",false); fapi.createLabel(fapi.toAddr(0xB04A9),"Mirrored_AN82527_Message13-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x800DC),"AN82527_Message13-Data5",false); fapi.createLabel(fapi.toAddr(0xB04AA),"Mirrored_AN82527_Message13-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x800DD),"AN82527_Message13-Data6",false); fapi.createLabel(fapi.toAddr(0xB04AB),"Mirrored_AN82527_Message13-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x800DE),"AN82527_Message13-Data7",false); fapi.createLabel(fapi.toAddr(0xB04AC),"Mirrored_AN82527_Message13-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x800DF),"AN82527_Port1_Out",false); fapi.createLabel(fapi.toAddr(0xB04AD),"Mirrored_AN82527_Port1_Out",false); 
		fapi.createLabel(fapi.toAddr(0x800E0),"AN82527_Message14-Control0",false); fapi.createLabel(fapi.toAddr(0xB04AE),"Mirrored_AN82527_Message14-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x800E1),"AN82527_Message14-Control1",false); fapi.createLabel(fapi.toAddr(0xB04AF),"Mirrored_AN82527_Message14-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x800E2),"AN82527_Message14-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB04B0),"Mirrored_AN82527_Message14-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x800E3),"AN82527_Message14-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB04B1),"Mirrored_AN82527_Message14-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x800E4),"AN82527_Message14-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB04B2),"Mirrored_AN82527_Message14-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x800E5),"AN82527_Message14-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB04B3),"Mirrored_AN82527_Message14-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x800E6),"AN82527_Message14-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB04B4),"Mirrored_AN82527_Message14-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800E7),"AN82527_Message14-Data0",false); fapi.createLabel(fapi.toAddr(0xB04B5),"Mirrored_AN82527_Message14-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x800E8),"AN82527_Message14-Data1",false); fapi.createLabel(fapi.toAddr(0xB04B6),"Mirrored_AN82527_Message14-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x800E9),"AN82527_Message14-Data2",false); fapi.createLabel(fapi.toAddr(0xB04B7),"Mirrored_AN82527_Message14-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x800EA),"AN82527_Message14-Data3",false); fapi.createLabel(fapi.toAddr(0xB04B8),"Mirrored_AN82527_Message14-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x800EB),"AN82527_Message14-Data4",false); fapi.createLabel(fapi.toAddr(0xB04B9),"Mirrored_AN82527_Message14-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x800EC),"AN82527_Message14-Data5",false); fapi.createLabel(fapi.toAddr(0xB04BA),"Mirrored_AN82527_Message14-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x800ED),"AN82527_Message14-Data6",false); fapi.createLabel(fapi.toAddr(0xB04BB),"Mirrored_AN82527_Message14-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x800EE),"AN82527_Message14-Data7",false); fapi.createLabel(fapi.toAddr(0xB04BC),"Mirrored_AN82527_Message14-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x800EF),"AN82527_Port2_Out",false); fapi.createLabel(fapi.toAddr(0xB04BD),"Mirrored_AN82527_Port2_Out",false); 
		fapi.createLabel(fapi.toAddr(0x800F0),"AN82527_Message15-Control0",false); fapi.createLabel(fapi.toAddr(0xB04BE),"Mirrored_AN82527_Message15-Control0",false); 
		fapi.createLabel(fapi.toAddr(0x800F1),"AN82527_Message15-Control1",false); fapi.createLabel(fapi.toAddr(0xB04BF),"Mirrored_AN82527_Message15-Control1",false); 
		fapi.createLabel(fapi.toAddr(0x800F2),"AN82527_Message15-Arbitration0",false); fapi.createLabel(fapi.toAddr(0xB04C0),"Mirrored_AN82527_Message15-Arbitration0",false); 
		fapi.createLabel(fapi.toAddr(0x800F3),"AN82527_Message15-Arbitration1",false); fapi.createLabel(fapi.toAddr(0xB04C1),"Mirrored_AN82527_Message15-Arbitration1",false); 
		fapi.createLabel(fapi.toAddr(0x800F4),"AN82527_Message15-Arbitration2",false); fapi.createLabel(fapi.toAddr(0xB04C2),"Mirrored_AN82527_Message15-Arbitration2",false); 
		fapi.createLabel(fapi.toAddr(0x800F5),"AN82527_Message15-Arbitration3",false); fapi.createLabel(fapi.toAddr(0xB04C3),"Mirrored_AN82527_Message15-Arbitration3",false); 
		fapi.createLabel(fapi.toAddr(0x800F6),"AN82527_Message15-Message_Configuration",false); fapi.createLabel(fapi.toAddr(0xB04C4),"Mirrored_AN82527_Message15-Message_Configuration",false); 
		fapi.createLabel(fapi.toAddr(0x800F7),"AN82527_Message15-Data0",false); fapi.createLabel(fapi.toAddr(0xB04C5),"Mirrored_AN82527_Message15-Data0",false); 
		fapi.createLabel(fapi.toAddr(0x800F8),"AN82527_Message15-Data1",false); fapi.createLabel(fapi.toAddr(0xB04C6),"Mirrored_AN82527_Message15-Data1",false); 
		fapi.createLabel(fapi.toAddr(0x800F9),"AN82527_Message15-Data2",false); fapi.createLabel(fapi.toAddr(0xB04C7),"Mirrored_AN82527_Message15-Data2",false); 
		fapi.createLabel(fapi.toAddr(0x800FA),"AN82527_Message15-Data3",false); fapi.createLabel(fapi.toAddr(0xB04C8),"Mirrored_AN82527_Message15-Data3",false); 
		fapi.createLabel(fapi.toAddr(0x800FB),"AN82527_Message15-Data4",false); fapi.createLabel(fapi.toAddr(0xB04C9),"Mirrored_AN82527_Message15-Data4",false); 
		fapi.createLabel(fapi.toAddr(0x800FC),"AN82527_Message15-Data5",false); fapi.createLabel(fapi.toAddr(0xB04CA),"Mirrored_AN82527_Message15-Data5",false); 
		fapi.createLabel(fapi.toAddr(0x800FD),"AN82527_Message15-Data6",false); fapi.createLabel(fapi.toAddr(0xB04CB),"Mirrored_AN82527_Message15-Data6",false); 
		fapi.createLabel(fapi.toAddr(0x800FE),"AN82527_Message15-Data7",false); fapi.createLabel(fapi.toAddr(0xB04CC),"Mirrored_AN82527_Message15-Data7",false); 
		fapi.createLabel(fapi.toAddr(0x800FF),"AN82527_Serial_Reset_Address",false); fapi.createLabel(fapi.toAddr(0xB04CD),"Mirrored_AN82527_Serial_Reset_Address",false); 

	}
	
	
	
	private void mainCalLabels(FlatProgramAPI fapi) throws Exception
	{
		Address address = fapi.toAddr(0x080000);
		MemoryBlock mb = fapi.createMemoryBlock("AN82527", address, null, 0xff, false);
		mb.setWrite(true);
	}
	
	
	
	private void calLabels(FlatProgramAPI fapi) throws Exception
	{
		fapi.createLabel(fapi.toAddr(0x0200),"Start",false);
		
		Address address = fapi.toAddr(0x030000);
		
		MemoryBlock mb = fapi.getMemoryBlock(address);
		if (mb == null)
		{
			mb = fapi.createMemoryBlock("TPUflash", address, null, 0x1000, false);
		}
		mb.setExecute(true);
		
		address = fapi.toAddr(0x0B0000);
		mb = fapi.createMemoryBlock("SRAM", address, null, 0x1000, false);
		mb.setWrite(true);
		mb.setExecute(true);
		
		address = fapi.toAddr(0x0B1000);
		mb = fapi.createMemoryBlock("RSPI", address, null, 0xc00, false);
		mb.setWrite(true);
		
		String[][] vectorTable = 
			{
					{"0x70", "PortF"},
					{"0x80", "TPU2Ch0"},
					{"0x104", "MCSM2"},
					{"0x106", "DASM3"},
					{"0x108", "DASM4"},
					{"0x10a", "DASM5"},
					{"0x10c", "DASM6"},
					{"0x10e", "DASM7"},
					{"0x110", "DASM8"},
					{"0x112", "PWMSM9"},
					{"0x114", "PWMSM10"},
					{"0x116", "PWMSM11"},
					{"0x118", "PWMSM12"},
					{"0x11a", "PWMSM13"},
					{"0x11c", "DASM14"},
					{"0x11e", "DASM15"},
					{"0x120", "DASM16"},
					{"0x122", "DASM17"},
					{"0x124", "DASM18"},
					{"0x126", "MCSM19"},
					{"0x128", "DASM20"},
					{"0x12a", "MCSM21"},
					{"0x12c", "DASM22"},
					{"0x12e", "MCSM23"},
					{"0xc0", "QADC_Queue1_pause"},
					{"0xc2", "QADC_Queue1_completion"},
					{"0xc4", "QADC_Queue2_pause"},
					{"0xc6", "QADC_Queue2_completion"},
					{"0xb8", "RSPI"},
					{"0x78", "MCCI_SCIA"},
					{"0x7a", "MCCI_SCIB"},
					{"0x7c", "MCCI_SPI"},
			};
		
		for (String[] s : vectorTable)
		{
			createVector(fapi, s[0], s[1]);
		}
		
		//special routine for TPU2 channels 0 - 15, starting at location 0x80
		for (int x=0; x<16 ; x++)
		{
			createVector(fapi, Integer.toHexString(2*x+0x80), "TPU2Ch"+Integer.toString(x));
		}
				
	}
	
	
	//---------------------------------------------------------
	
	
	void createVector(FlatProgramAPI fapi, String addr, String name) throws Exception
	{
		Address address = fapi.toAddr(addr);
		Data pointer16 = fapi.getDataAt(address);
		if (pointer16 == null)
		{
			pointer16 = fapi.createData(address, Pointer16DataType.dataType);
		}
		
		Symbol sym = fapi.getSymbolAt(address);
		if (sym != null)
		{
			fapi.removeSymbol(address, sym.getName());
		}
		fapi.createLabel(address,name+"_IV",false);
		
		Address funAddress = (Address) pointer16.getValue();
		Function fun = fapi.getFunctionAt(funAddress);
		if (fun != null)
		{
			fapi.removeFunction(fun);
		}
		fapi.createFunction(funAddress,name+"_ISR");
	}
}
