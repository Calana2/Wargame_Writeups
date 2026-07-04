class Solution(object):
    def solveSudoku(self, board):
        if (self.solve(board)):
            return board
        return None
    
    def solve(self, board):
        for i in range(9):
            for j in range(9):
                if board[i][j] == '.':
                    for num in '123456789':
                        if self.isValid(board, i, j, num):
                            board[i][j] = num
                            if self.solve(board):
                                return True
                            board[i][j] = '.'  # Backtrack
                    return False
        return True
    
    def isValid(self, board, row, col, num):
        # Each horizontal row can only contain numbers from 1 to 9.
        for j in range(9):
            if board[row][j] == num:
                return False
        # Each vertical column can only contain numbers from 1 to 9.
        for i in range(9):
            if board[i][col] == num:
                return False
        # Each 3×3 block can only contain numbers from 1 to 9.
        block_row = (row // 3) * 3
        block_col = (col // 3) * 3
        for i in range(block_row, block_row + 3):
            for j in range(block_col, block_col + 3):
                if board[i][j] == num:
                    return False
        return True
