#!/usr/bin/python3
"""
Various multipart extractors are here.
"""
import pdb
import traceback

class Extractor:
    def __init__(self, data):
        self.data = bytes(data)


class SMTPExtractor(Extractor):
    def __init__(self, data):
        super().__init__(data)
        content_type = b''
        start_boundaries = []
        end_boundaries = []
        self.content = {}

        # find main Content-Type header
        lines = self.data.split(b'\n')
        for i, line in enumerate(lines):
            if not line.strip(): # end of headers, stop searching
                break
            if line.startswith(b'Content-Type:'):
                content_type = line.partition(b': ')[2].partition(b';')[0]
                try:
                    boundary = lines[i+1].partition(b'=')[2].strip().strip(b'"')
                    start_boundaries.append(b'--' + boundary)
                    end_boundaries.append(b'--' + boundary + b'--')
                except:
                    break

        if content_type == b'multipart/mixed':
            if boundary:
                start_boundary = b'--' + boundary
                end_boundary = start_boundary + b'--'

                part_lines = []
                in_part = False

                skip_until = 0

                for i in range(len(lines)):
                    if i <= skip_until:
                        continue
                    line = lines[i]
                    
                    # interuption of the part
                    if line.strip() in end_boundaries or (in_part and line.strip() in start_boundaries):
                        in_part = False
                        # store if we have something so far
                        if part_lines and not part_content_type.startswith(b'multipart/'):
                            # craft name if none
                            if not part_name:
                                if part_content_type == b'text/plain':
                                    part_name = b'text'
                                elif part_content_type == b'text/html':
                                    part_name = b'html'

                                else:
                                    part_name = b'unknown_%d' % i

                            # decode if possible
                            data = b'\n'.join(part_lines + [b''])
                            if part_content_transfer_encoding == b'7bit':
                                pass
                            elif part_content_transfer_encoding == b'quoted-printable':
                                pass
                            else:
                                print('Unknown Content-Transfer-Encoding {part_content_transfer_encoding}, treating as raw.')
                            # store gathered
                            print(f'saving {part_name}: "{data[:5]}...{data[-5:]}"')
                            self.content[part_name] = data

                    # actually start of new part
                    if line.strip() in start_boundaries:
                        # start over
                        part_lines = []
                        part_content_type = b''
                        part_content_transfer_encoding = b''
                        part_content_disposition = b''
                        part_name = b''
                        in_part = True

                        # find important headers for actual part
                        for j in range(i+1, len(lines)):
                            jline = lines[j].strip()
                            if not jline.strip():
                                skip_until = j
                                break
                            colon_part = jline.partition(b': ')
                            if colon_part[0] == b'Content-Type':
                                part_content_type = colon_part[2].partition(b';')[0]
                            elif colon_part[0] == b'Content-Transfer-Encoding':
                                part_content_transfer_encoding = colon_part[2].partition(b';')[0]
                            elif colon_part[0] == b'Content-Disposition':
                                part_content_disposition = colon_part[2].partition(b';')[0]
                            else:
                                eq_part = jline.partition(b'=')
                                if eq_part[0] in (b'name', b'filename'):
                                    part_name = eq_part[2].strip(b'"')
                                if eq_part[0] == b'boundary' and part_content_type.startswith(b'multipart/'):
                                    boundary = eq_part[2].strip(b'"')
                                    start_boundaries.append(b'--' + boundary)
                                    end_boundaries.append(b'--' + boundary + b'--')
                        #print(f'continuing with i {skip_until}')
                        continue

                    if in_part: # part data
                        part_lines.append(line) 
            else:
                print(' Missing multipart boundary.')
        else:
            print(f' Unknown Content-Type {content_type}.')




