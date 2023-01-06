import sys
import os
import json
import hashlib
from PIL import Image, UnidentifiedImageError
from PIL.ExifTags import TAGS

__license__ = "GPL3"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PHOTOORG_JSON = "photoorg.json"

NAME = "NAME"
EXIF = "EXIF"
ITEMS = "ITEMS"

FILENAME = "FILENAME"
HASH = "HASH"
NOT_AN_IMAGE = "NOT_AN_IMAGE"

#EXIF_EXCLUDE = ["PrintImageMatching", "ComponentsConfiguration", "FileSource", "SceneType", "MakerNote"]
EXIF_EXCLUDE = []

#old
ATTRIBUTES = "ATTRIBUTES"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getBlurb():
	return '''    ____  __          __           ____            
   / __ \/ /_  ____  / /_____     / __ \_________ _
  / /_/ / __ \/ __ \/ __/ __ \   / / / / ___/ __ `/
 / ____/ / / / /_/ / /_/ /_/ /  / /_/ / /  / /_/ / 
/_/   /_/ /_/\____/\__/\____/   \____/_/   \__, /  
                                          /____/   '''


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()
	
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getFileData(file, config):
	result = {}
	
	result[NAME] = file
	result[FILENAME] = file
	result[EXIF] = {}
	result[ITEMS] = None
	
	# hash for comparisons
	result[HASH] = sha256sum(file)
	
	if ("quick" not in config):
		# get EXIF tags
		try:
			exif = Image.open(file).getexif()
			if (exif is not None):
				for (k,v) in exif.items():
					if (k in TAGS and TAGS[k] not in EXIF_EXCLUDE):
						result[EXIF][TAGS[k]] = str(v)
					else:
						result[EXIF][k] = str(v)
		except UnidentifiedImageError:
			# not an image, flag it
			result[NOT_AN_IMAGE] = "True"
	
	return result	

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def scanDir(root, base, index, config):
	
	result = {}
	result[NAME] = root
	result[EXIF] = None
	result[ITEMS] = {}
	
	print("... %s" % root)
	
	with os.scandir(root) as entries:
		for entry in entries:
			p = os.path.join(root, entry)
			if os.path.isfile(p):
			
				head, file_name = os.path.split(p)
				if (file_name == PHOTOORG_JSON):
					continue
				
				id = os.path.relpath(p, base)
				if (ITEMS in index and id in index[ITEMS]):
					# copy from existing index
					result[ITEMS][id] = index[ITEMS][id]
					
					# missing a hash - get it all anyway
					if (HASH not in result[ITEMS][id]):
						result[ITEMS][id] = getFileData(p, config)
				else:
					# fetch file data fresh
					result[ITEMS][id] = getFileData(p, config)
			elif os.path.isdir(p):
				id = os.path.relpath(p, base)
				if (ITEMS in index and id in index[ITEMS]):
					# pass in the subindex
					result[ITEMS][id] = scanDir(p, base, index[ITEMS][id], config)
				else:
					# not in the index
					result[ITEMS][id] = scanDir(p, base, {}, config)
			else:
				raise("unknown item "+p)
	
	return result

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def printDebug(d, prefix=""):

	print(prefix + d[NAME])
	
	if (d[EXIF] is not None and len(d[EXIF]) > 0):
		print(prefix+str(d[EXIF]))
	
	if (d[ITEMS] is not None and len(d[ITEMS]) > 0):
		for item in d[ITEMS]:
			printDebug(item, prefix+"  ")

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def getJson(d):
	return json.dumps(d, indent=1)
	
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def diff(index1, index2):
	
	name1 = index1[NAME]
	name2 = index2[NAME]
	
	#if (index1[NAME] != index2[NAME]):
	#	print("different indexes (%s, %s), will not diff" % (index1[NAME], index2[NAME]))
	
	items1 = len(index1[ITEMS])
	items2 = len(index2[ITEMS])
	
	#print(items1)
	#print(items2)
	
	#if (items1 != items2):
	#	print("different number of items: %s (%s) vs %s (%s)" % (items1, name1, items2, name2))
		
	missing_in_index1 = []
	missing_in_index2 = []
	different_hash = []
	
	for k in index1[ITEMS]:
		if (k in index2[ITEMS]):
			# is in both indices
			item1 = index1[ITEMS][k]
			item2 = index2[ITEMS][k]
			
			# check the hashes
			if (HASH in item1):
				hash1 = item1[HASH]
				
				if (HASH not in item2):
					print("ERROR: no hash on '%s'" % (item2[NAME]))
				else:
					hash2 = item2[HASH]
					if (hash1 != hash2):
						different_hash.append( (item1, item2) )
			elif (item1[ITEMS] == None or len(item1[ITEMS])==0):
				# should be a hash on every file, not on folders
				print("ERROR: no hash on '%s'" % (item1[NAME]))
			
			if (item1[ITEMS] is not None):
				(a, b, c) = diff(item1, item2)
				missing_in_index1 += a
				missing_in_index2 += b
				different_hash += c
		else:
			missing_in_index2.append(index1[ITEMS][k])
	
	for k in index2[ITEMS]:
		if (k not in index1[ITEMS]):
			missing_in_index1.append(index2[ITEMS][k])
	
	return (missing_in_index1, missing_in_index2, different_hash)
	
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def exifTagDiff(tag, file1_data, file2_data):
	return tag in file1_data and tag in file2_data and file1_data[tag] == file2_data[tag]

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def diffImages(file1, file2):

	file1_data = getFileData(file1, {})
	file2_data = getFileData(file2, {})
	
	# compare hash
	if (file1_data[HASH] != file2_data[HASH]):
		print("Different hashes:\n[%s]\n[%s]" % (file1_data[HASH], file2_data[HASH]))
	else:
		print("Same hash [%s]" % file1_data[HASH])

	# detect invalid images
	if (NOT_AN_IMAGE in file1_data):
		print("%s is not a valid image" % file1_data[NAME])
	if (NOT_AN_IMAGE in file2_data):
		print("%s is not a valid image" % file2_data[NAME])
	if (NOT_AN_IMAGE in file1_data or NOT_AN_IMAGE in file2_data):
		return
	
	# compare EXIF
	exif_same = 0
	for k in file1_data[EXIF]:
		if (k not in file2_data[EXIF]):
			print("EXIF %s missing in %s" % (k, file2))
		elif (file1_data[EXIF][k] != file2_data[EXIF][k]):
			print("Different EXIF: [%s] = [%s] vs [%s]" % (k, file1_data[EXIF][k], file2_data[EXIF][k]))
		else:
			exif_same += 1
	print("%s identical EXIF tags" % exif_same)
	
	# compare pixels
	file1_image = Image.open(file1)
	file2_image = Image.open(file2)

	width1, height1 = file1_image.size
	width2, height2 = file1_image.size
	
	if (width1 != width2):
		print("Different widths %s vs %s" % width1, width2)
	if (height1 != height2):
		print("Different heights %s vs %s" % height1, height2)
		
	# only makes sense comparing pixels under certain conditions
	compare_pixels = True
	
	compare_pixels &= width1 == width2
	compare_pixels &= height1 == height2
	compare_pixels &= exifTagDiff("Orientation", file1_data[EXIF], file2_data[EXIF])
	compare_pixels &= exifTagDiff("ExifOffset", file1_data[EXIF], file2_data[EXIF])
	
	if (compare_pixels):
		file1_pixels = file1_image.load()
		file2_pixels = file2_image.load()

		diff_image = Image.new('RGB', (width1, height1))
		diff_pixels = diff_image.load()
		
		pixel_count = 0;
		for y in range(height1):
			for x in range(width1):			
				file1_color = file1_pixels[x, y]
				file2_color = (255,255,255)
				try:
					file2_color = file2_pixels[x, y]
				except:
					pass
				diff_color = (abs(file1_color[0] - file2_color[0]), abs(file1_color[1] - file2_color[1]), abs(file1_color[2] - file2_color[2]))
				diff_pixels[x, y] = diff_color
				if (sum(diff_color) != 0):
					pixel_count += 1
				
		print("%s pixels different" % pixel_count)
	#diff_image.save('diff.jpg')
	
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def indexHashes(root):
	
	result = {}
	
	hash_collisions = []
	
	if (ITEMS not in root or root[ITEMS] is None):
		return result
	
	for k in root[ITEMS]:
		item = root[ITEMS][k]
		if (HASH in item):
			h = item[HASH]
			if (h in result):
				hash_collisions.append( (h, item[NAME], result[h][FILENAME]) )
			else:
				result[h] = item
		else:
			(h,c) = indexHashes(item)
			result = result | h
			hash_collisions = hash_collisions + c
	
	return (result, hash_collisions)
	
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# find each image in index1 in index2, based on hash
def find(index1, index2):
	
	if (index1[ITEMS] is None):
		print("no images to find in %s" % index1[NAME]);
		return
	
	map = indexHashes(index2)[0]
	
	not_found = []
	
	for k in index1[ITEMS]:
		item = index1[ITEMS][k]
		if (item[HASH] is not None):
			if (item[HASH] in map):
				print("found [%s] at [%s]" % (item[FILENAME], map[item[HASH]][FILENAME]))
			else:
				not_found.append(item)
	
	for item in not_found:
		print("NOT FOUND: [%s]" % item[FILENAME])
	
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def quickFixOldFormat(item):
	if (ATTRIBUTES in item and item[ATTRIBUTES] is not None):
		item[EXIF] = item[ATTRIBUTES]
		
		if (FILENAME in item[ATTRIBUTES]):
			item[FILENAME] = item[ATTRIBUTES][FILENAME]
			del item[EXIF][FILENAME]
		else:
			item[FILENAME] = item[NAME]
		
		if (NOT_AN_IMAGE in item[ATTRIBUTES]):
			item[NOT_AN_IMAGE] = item[ATTRIBUTES][NOT_AN_IMAGE]
			del item[EXIF][NOT_AN_IMAGE]
		
		del item[ATTRIBUTES]
	
	if (FILENAME not in item):
		item[FILENAME] = item[NAME]

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# print commands to sync from index1 to index2
def sync(index1, index2):
	
	(missing_in_index1, missing_in_index2, different_hash) = diff(index1, index2)
	
	# for items that missing in index1, delete from index2
	for item in missing_in_index1:
		quickFixOldFormat(item)
		index2_path = item[FILENAME]
		print('del "%s"' % index2_path)

	print()
	
	# for items that missing in index2, copy over from index1
	for item in missing_in_index2:
		quickFixOldFormat(item)
		index2_path = os.path.join(index2[NAME], os.path.relpath(item[FILENAME], index1[NAME]))
		index1_path = item[FILENAME]
		print('echo F|xcopy "%s" "%s" /Y' % (index1_path, index2_path))


	print()

	# for items that show up different, overwrite those in index2
	for (item1, item2) in different_hash:
		quickFixOldFormat(item1)	
		quickFixOldFormat(item2)
		print('echo F|xcopy "%s" "%s" /Y' % (item1[NAME], item2[NAME]))

	print()

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if __name__ == "__main__":

	print(getBlurb())
	
	op = sys.argv[1]
	
	if (op == "index"):
		
		config = {}
	
		dir = sys.argv[2]
		
		if (len(sys.argv) >= 4):
			flags = sys.argv[3:]
			
			if ("-quick" in flags):
				config["quick"] = True
			if ("-update" in flags):
				config["update"] = True
		
		index_file = os.path.join(dir, PHOTOORG_JSON)
				
		r = {}
		if ("update" in config):
			index = json.load(open(index_file,"r"))
			r = scanDir(dir, dir, index, config)
		else:
			r = scanDir(dir, dir, r, config)
		
		s = getJson(r)
		
		with open(index_file, "w") as file:
			file.write(s)
		
		print("indexed to %s" % (index_file))
	
	elif (op == "diff"):
		dir1 = sys.argv[2]
		dir2 = sys.argv[3]
		
		index1 = None
		index2 = None
		
		index_file1 = open(os.path.join(dir1, PHOTOORG_JSON), "r")
		index1 = json.load(index_file1)

		index_file2 = open(os.path.join(dir2, PHOTOORG_JSON), "r")
		index2 = json.load(index_file2)
		
		(missing_in_index1, missing_in_index2, different_hash) = diff(index1, index2)
		
		###
		if (len(missing_in_index1) > 0):
			print("Missing in %s:" % index1[NAME])
			for item in missing_in_index1:
				print(item[NAME])

		if (len(missing_in_index2) > 0):
			print("Missing in %s:" % index2[NAME])
			for item in missing_in_index2:
				print(item[NAME])
			
		if (len(different_hash) > 0):
			print("Mismatched hash:")
			for (item1, item2) in different_hash:
				print("[%s] vs [%s]" % (item1[NAME], item2[NAME]))
				quickFixOldFormat(item1)	
				quickFixOldFormat(item2)
				diffImages(item1[FILENAME], item2[FILENAME])
				print("")
	
	elif (op == "diff-images"):
		file1 = sys.argv[2]
		file2 = sys.argv[3]
		
		diffImages(file1, file2)
	
	elif (op == "sync"):
		dir1 = sys.argv[2]
		dir2 = sys.argv[3]
		
		index1 = None
		index2 = None
		
		index_file1 = open(os.path.join(dir1, PHOTOORG_JSON), "r")
		index1 = json.load(index_file1)

		index_file2 = open(os.path.join(dir2, PHOTOORG_JSON), "r")
		index2 = json.load(index_file2)

		sync(index1, index2)
	
	elif (op == "find"):
		dir1 = sys.argv[2]
		dir2 = sys.argv[3]

		index1 = None
		index2 = None

		index_file1 = open(os.path.join(dir1, PHOTOORG_JSON), "r")
		index1 = json.load(index_file1)

		index_file2 = open(os.path.join(dir2, PHOTOORG_JSON), "r")
		index2 = json.load(index_file2)
		
		find(index1, index2)
	
	elif (op == "dedupe"):
		dir1 = sys.argv[2]
		
		index1 = None

		index_file1 = open(os.path.join(dir1, PHOTOORG_JSON), "r")
		index1 = json.load(index_file1)
		
		collisions = indexHashes(index1)[1]
		
		for h in collisions:
			print("hash collision on %s\n  [%s]\n  [%s]" % (h[0], h[1], h[2]))
		
		if (len(collisions) > 0):
			print("\n\nDELETION SCRIPTS:\n\n")
			for h in collisions:
				print('del "%s"' % h[1])
	
		
		
		
			
		
	
	
	
	
	
