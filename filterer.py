import pandas as pd 

class nx_filter(object):

	def __init__(self, data=None, filters=None):
		self.data = data
		#self.row_filters = filters{"rows"}
		#self.col_filters = filters{"columns"}