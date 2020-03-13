##
# Copyright (c) 2016, Gabor Gyorgy Gulyas
# Email: gulyas@pet-portal.eu
# Web: gulyas.info
##

from scipy.spatial.distance import cdist
import math
import matplotlib
import numpy as np

def selectpoints(ax, points, radius = .1, ec='b', ls='-', lw=2, fc='g', a=.5, fill=True, js='round'):
	# Add "bounds" to each point
	points_ = []
	for ix in range(len(points)):
		for _ in [0]+[(2*math.pi*x)/16 for x in range(1,16)]:
			points_.append([points[ix][0] + radius * math.cos(_), points[ix][1] + radius * math.sin(_)])

	points = points_

	# Select points that are on the border
	border = []
	for ix in range(len(points)):
		angles = []
		for ix2 in range(len(points)):
			if ix != ix2:
				angle = math.degrees(math.atan2(points[ix2][1]-points[ix][1], points[ix2][0]-points[ix][0]))
				if angle < 0:
					angle += 360
				angles.append(angle)
		angles = sorted(angles)
		diffs = []
		for ix2 in range(len(angles)-1):
			diffs.append(angles[ix2+1]-angles[ix2])
		diffs.append(360-angles[len(angles)-1] + angles[0])
		if max(diffs) > 180:
			border.append(points[ix])

	# Calculate center
	cx = float(sum([pt[0] for pt in border])) / len(border)
	cy = float(sum([pt[1] for pt in border])) / len(border)

	# Reorder points on the border counter-clockwise
	for ix in range(len(border)):
		angle = math.degrees(math.atan2(border[ix][1]-cy, border[ix][0]-cx))
		if angle < 0:
			angle += 360
		border[ix].append(angle)
	border = sorted(border, key=lambda x: x[2])

	# Construct patch to cover points and plot it
	path_data = [(matplotlib.path.Path.MOVETO, (border[0][0], border[0][1]))]
	for pt in border[1:-1]:
		path_data.append((matplotlib.path.Path.LINETO, (pt[0], pt[1])))
	path_data.append((matplotlib.path.Path.LINETO, (border[-1][0], border[-1][1])))
	path_data.append((matplotlib.path.Path.CLOSEPOLY, (border[0][0], border[0][1])))

	codes, verts = zip(*path_data)
	mypath = matplotlib.path.Path(verts, codes)
	patch = matplotlib.patches.PathPatch(mypath, edgecolor=ec, linestyle=ls, linewidth=lw, facecolor=fc, fill=fill, alpha=a, joinstyle=js)
	ax.add_patch(patch)

	# Calculate shape radius
	r = max(cdist(np.array([[cx, cy]]), np.array(border)[:,:2], 'euclidean')[0].tolist())
	return [cx, cy], r