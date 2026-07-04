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
        row, col = int(row), int(col)
        for i in range(9):
             # Each horizontal row can only contain numbers from 1 to 9.
            if board[row][i] == num:
                return False
            # Each vertical column can only contain numbers from 1 to 9.
            if board[i][col] == num:
                return False
            # Each 3×3 block can only contain numbers from 1 to 9.
            if board[3*(row // 3) + i//3][3*(col // 3) + i%3] == num:
                return False
        return True
